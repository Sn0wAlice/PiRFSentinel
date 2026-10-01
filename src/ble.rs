//! BLE advertisements via BlueZ (bluer), duplicates included so RSSI keeps flowing.
//! BlueZ only reports property *changes*, so a local copy of each device is kept
//! and re-emitted as a full Advert on every change.

use crate::detect::{now_ms, AddressType, Advert, Source};
use crate::Input;
use bluer::{AdapterEvent, Address, DeviceEvent, DeviceProperty, DiscoveryFilter, DiscoveryTransport};
use futures::stream::{abortable, AbortHandle, SelectAll, StreamExt};
use std::collections::HashMap;
use tokio::sync::mpsc;

pub async fn run(tx: mpsc::Sender<Input>) -> bluer::Result<()> {
    let session = bluer::Session::new().await?;
    let adapter = session.default_adapter().await?;
    adapter.set_powered(true).await?;
    adapter.set_discovery_filter(DiscoveryFilter {
        transport: DiscoveryTransport::Le,
        duplicate_data: true,
        ..Default::default()
    }).await?;
    crate::ui::note(&crate::ui::dim(&format!("  ble: scanning on {}", adapter.name())));
    let mut disco = adapter.discover_devices().await?;
    let mut changes = SelectAll::new();
    // One property stream per device; aborted when BlueZ forgets the device
    // (unpaired devices expire ~30 s after their last advert).
    let mut devices: HashMap<Address, (Advert, AbortHandle)> = HashMap::new();

    loop {
        tokio::select! {
            Some(ev) = disco.next() => match ev {
                AdapterEvent::DeviceAdded(addr) if !devices.contains_key(&addr) => {
                    let dev = adapter.device(addr)?;
                    let mut a = Advert::new(&addr.to_string(), Source::Ble, i16::MIN);
                    a.address_type = match dev.address_type().await {
                        Ok(bluer::AddressType::LePublic) | Ok(bluer::AddressType::BrEdr) => AddressType::Public,
                        Ok(bluer::AddressType::LeRandom) => AddressType::of_random(&a.mac),
                        Err(_) => AddressType::Unknown,
                    };
                    for p in dev.all_properties().await.unwrap_or_default() {
                        apply(&mut a, p);
                    }
                    let Ok(events) = dev.events().await else { continue };
                    let (events, handle) = abortable(events);
                    changes.push(events.map(move |e| (addr, e)));
                    if a.rssi != i16::MIN && tx.send(Input::Advert(a.clone())).await.is_err() {
                        return Ok(());
                    }
                    devices.insert(addr, (a, handle));
                }
                AdapterEvent::DeviceRemoved(addr) => {
                    if let Some((_, h)) = devices.remove(&addr) {
                        h.abort();
                    }
                }
                _ => {}
            },
            Some((addr, DeviceEvent::PropertyChanged(p))) = changes.next() => {
                let Some((a, _)) = devices.get_mut(&addr) else { continue };
                if apply(a, p) && a.rssi != i16::MIN {
                    a.timestamp = now_ms();
                    if tx.send(Input::Advert(a.clone())).await.is_err() {
                        return Ok(());
                    }
                }
            }
            else => return Ok(()),
        }
    }
}

/// Applies one BlueZ property; true when it is radio data worth re-classifying.
fn apply(a: &mut Advert, p: DeviceProperty) -> bool {
    match p {
        DeviceProperty::Rssi(r) => a.rssi = r,
        DeviceProperty::Name(n) => a.name = Some(n),
        DeviceProperty::TxPower(t) => a.tx_power = Some(t),
        DeviceProperty::ManufacturerData(m) => a.manufacturer_data = m,
        DeviceProperty::ServiceData(d) => a.service_data = d,
        DeviceProperty::Uuids(u) => {
            let mut v: Vec<_> = u.into_iter().collect();
            v.sort();
            a.service_uuids = v;
        }
        _ => return false,
    }
    true
}
