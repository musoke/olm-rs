// Based on https://github.com/ruma/ruma-client/blob/master/examples/hello_world_await.rs
#![feature(conservative_impl_trait)]
#![feature(generators)]
#![feature(proc_macro)]
#![feature(try_from)]

extern crate futures_await as futures;
extern crate olm;
extern crate ruma_client;
extern crate ruma_events;
extern crate ruma_identifiers;
extern crate tokio_core;
extern crate url;

use std::convert::TryFrom;
use std::env;
use std::process::exit;

use futures::prelude::*;
use ruma_client::Client;
use ruma_client::api::r0;
use ruma_client::api::unstable;
use ruma_events::EventType;
use ruma_events::room::message::{MessageEventContent, MessageType, TextMessageEventContent};
use ruma_identifiers::RoomAliasId;
use tokio_core::reactor::{Core, Handle};
use url::Url;

use std::collections::HashMap;
use olm::device::LocalDevice;

fn hello_world(
    tokio_handle: &Handle,
    homeserver_url: Url,
    room: String,
) -> impl Future<Item = (), Error = ruma_client::Error> + 'static {
    let client = Client::https(tokio_handle, homeserver_url, None).unwrap();

    async_block! {
        let session = await!(client.register_guest())?;

        let my_dev = LocalDevice::init(session.user_id().clone()).unwrap();
        let dev_keys = my_dev.olm_acount_identity_keys();

        // No keys yet, so this should return an empty list
        let response = await!(
            unstable::keys::upload::call(client.clone(), unstable::keys::upload::Request {
                device_keys: None,
                one_time_keys: None,
            })
        );
        println!("Before uploading one-time keys: {:?}", response);

        // A faked one-time key for now.  Will generate an actual one later.
        let mut one_time_keys = HashMap::new();
        one_time_keys.insert(
            "curve25519:AAAAAQ".to_owned(),
            "/qyvZvwjiTxGdGU0RCguDCLeR+nmsb3FfNG3/Ve4vU8".to_owned(),
        );
        // Upload some keys, should now get a non-zero response...
        let response = await!(
            unstable::keys::upload::call(client.clone(), unstable::keys::upload::Request {
                device_keys: Some(dev_keys),
                one_time_keys: Some(one_time_keys),
            })
        );
        println!("After uploading one-time keys: {:?}", response);


        // let response = await!(r0::alias::get_alias::call(
        //     client.clone(),
        //     r0::alias::get_alias::Request {
        //         room_alias: RoomAliasId::try_from(&room[..]).unwrap(),
        //     }
        // ))?;

        // let room_id = response.room_id;

        // await!(r0::membership::join_room_by_id::call(
        //     client.clone(),
        //     r0::membership::join_room_by_id::Request {
        //         room_id: room_id.clone(),
        //         third_party_signed: None,
        //     }
        // ))?;

        // await!(r0::send::send_message_event::call(
        //     client.clone(),
        //     r0::send::send_message_event::Request {
        //         room_id: room_id,
        //         event_type: EventType::RoomMessage,
        //         txn_id: "1".to_owned(),
        //         data: MessageEventContent::Text(TextMessageEventContent {
        //             body: "Hello World!".to_owned(),
        //             msgtype: MessageType::Text,
        //         }),
        //     }
        // ))?;

        Ok(())
    }
}

fn main() {
    let (homeserver_url, room) = match (env::args().nth(1), env::args().nth(2)) {
        (Some(a), Some(b)) => (a, b),
        _ => {
            eprintln!(
                "Usage: {} <homeserver_url> <room>",
                env::args().next().unwrap()
            );
            exit(1)
        }
    };

    let mut core = Core::new().unwrap();
    let handle = core.handle();
    let server = Url::parse(&homeserver_url).unwrap();

    core.run(hello_world(&handle, server, room)).unwrap();
}
