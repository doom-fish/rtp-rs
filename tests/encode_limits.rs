use rtp::rtcp::app::App;
use rtp::rtcp::bye::Bye;
use rtp::rtcp::nack::{Nack, NackEntry};
use rtp::rtcp::remb::Remb;
use rtp::rtcp::rr::{ReceiverReport, ReportBlock};
use rtp::rtcp::sdes::{Sdes, SdesChunk, SdesItem};
use rtp::rtcp::sr::SenderReport;
use rtp::rtcp::twcc::{Delta, Twcc};
use rtp::{CompoundPacket, Error, Extension, Packet, RtcpPacket, RtpPacket};

const fn too_large(what: &'static str, max: usize, actual: usize) -> Error {
    Error::TooLarge { what, max, actual }
}

#[test]
fn report_block_counts_are_not_truncated() {
    let rr = ReceiverReport {
        ssrc: 1,
        reports: vec![ReportBlock::default(); 32],
    };
    assert_eq!(
        rr.encode(),
        Err(too_large("RTCP receiver report block count", 31, 32))
    );

    let sr = SenderReport {
        reports: vec![ReportBlock::default(); 32],
        ..SenderReport::default()
    };
    assert_eq!(
        sr.encode(),
        Err(too_large("RTCP sender report block count", 31, 32))
    );

    let full = ReceiverReport {
        ssrc: 1,
        reports: vec![ReportBlock::default(); 31],
    };
    let parsed = RtcpPacket::parse(&full.encode().unwrap()).unwrap();
    assert_eq!(parsed, RtcpPacket::ReceiverReport(full));
}

#[test]
fn sdes_limits_are_enforced() {
    let item = |len: usize| SdesItem {
        item_type: 1,
        text: vec![b'a'; len],
    };
    let long = Sdes {
        chunks: vec![SdesChunk {
            source: 1,
            items: vec![item(256)],
        }],
    };
    assert_eq!(
        long.encode(),
        Err(too_large("RTCP SDES item length", 255, 256))
    );

    let many = Sdes {
        chunks: vec![
            SdesChunk {
                source: 1,
                items: Vec::new(),
            };
            32
        ],
    };
    assert_eq!(
        many.encode(),
        Err(too_large("RTCP SDES chunk count", 31, 32))
    );

    let terminator = Sdes {
        chunks: vec![SdesChunk {
            source: 1,
            items: vec![SdesItem {
                item_type: 0,
                text: b"x".to_vec(),
            }],
        }],
    };
    assert!(matches!(terminator.encode(), Err(Error::BadPayload(_))));

    let max = Sdes {
        chunks: vec![SdesChunk {
            source: 7,
            items: vec![item(255)],
        }],
    };
    let parsed = RtcpPacket::parse(&max.encode().unwrap()).unwrap();
    assert_eq!(parsed, RtcpPacket::SourceDescription(max));
}

#[test]
fn bye_limits_are_enforced() {
    let many = Bye {
        sources: vec![1; 32],
        reason: None,
    };
    assert_eq!(
        many.encode(),
        Err(too_large("RTCP BYE source count", 31, 32))
    );

    let long_reason = Bye {
        sources: vec![1],
        reason: Some(vec![b'r'; 256]),
    };
    assert_eq!(
        long_reason.encode(),
        Err(too_large("RTCP BYE reason length", 255, 256))
    );

    let ok = Bye {
        sources: vec![1, 2],
        reason: Some(vec![b'r'; 255]),
    };
    let parsed = RtcpPacket::parse(&ok.encode().unwrap()).unwrap();
    assert_eq!(parsed, RtcpPacket::Bye(ok));
}

#[test]
fn app_subtype_must_fit_five_bits() {
    let app = App {
        subtype: 32,
        ssrc: 1,
        name: *b"TEST",
        data: Vec::new(),
    };
    assert_eq!(app.encode(), Err(too_large("RTCP APP subtype", 31, 32)));
}

#[test]
fn remb_ssrc_count_must_fit_one_byte() {
    let remb = Remb {
        sender_ssrc: 1,
        media_ssrc: 0,
        bitrate_bps: 1_000_000,
        ssrcs: vec![9; 256],
    };
    assert_eq!(remb.encode(), Err(too_large("REMB SSRC count", 255, 256)));
}

#[test]
fn twcc_status_count_must_fit_sixteen_bits() {
    let twcc = Twcc {
        statuses: vec![Delta::NotReceived; 65_536],
        ..Twcc::default()
    };
    assert_eq!(
        twcc.encode(),
        Err(too_large("TWCC packet status count", 65_535, 65_536))
    );
}

#[test]
fn rtcp_length_field_overflow_is_rejected() {
    let nack = Nack {
        sender_ssrc: 1,
        media_ssrc: 2,
        entries: vec![NackEntry { pid: 1, blp: 0 }; 65_534],
    };
    assert_eq!(
        nack.encode(),
        Err(too_large(
            "RTCP packet length in 32-bit words",
            65_535,
            65_536
        ))
    );

    let compound = CompoundPacket::new()
        .add(RtcpPacket::receiver_report().ssrc(1).build())
        .add(nack.into());
    assert!(compound.encode().is_err());
}

#[test]
fn rtp_builder_rejects_more_than_fifteen_csrcs() {
    let builder = (0..16).fold(
        RtpPacket::builder().payload([1]),
        rtp::RtpPacketBuilder::csrc,
    );
    assert_eq!(builder.build(), Err(too_large("CSRC count", 15, 16)));
}

#[test]
fn rtp_builder_pad_to_errors_instead_of_panicking() {
    let result = RtpPacket::builder().payload([1]).pad_to(257).build();
    assert_eq!(result, Err(too_large("padding alignment", 256, 257)));

    let bytes = RtpPacket::builder()
        .payload([0xAB])
        .pad_to(256)
        .build()
        .unwrap()
        .into_bytes();
    assert_eq!(bytes.len(), 256);
    let parsed = RtpPacket::parse(&bytes).unwrap();
    assert!(parsed.header().has_padding());
    assert_eq!(parsed.payload(), &[0xAB]);
}

#[test]
fn rtp_builder_reports_bad_extensions_as_errors() {
    let result = RtpPacket::builder()
        .extension(Extension::generic(0, [1]))
        .build();
    assert!(matches!(result, Err(Error::BadExtension(_))));
}

#[test]
fn rtp_builder_rejects_oversized_extension_blocks() {
    let builder = (0..1100u32).fold(RtpPacket::builder(), |b, i| {
        let id = u8::try_from(i % 255 + 1).unwrap();
        b.extension(Extension::generic(id, [0x5A; 255]))
    });
    assert!(matches!(
        builder.build(),
        Err(Error::TooLarge {
            what: "header extension length in 32-bit words",
            ..
        })
    ));
}
