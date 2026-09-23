use rtp::rtcp::app::App;
use rtp::rtcp::bye::Bye;
use rtp::rtcp::nack::{Nack, NackEntry};
use rtp::rtcp::remb::Remb;
use rtp::rtcp::rr::{ReceiverReport, ReportBlock};
use rtp::rtcp::sdes::{Sdes, SdesChunk, SdesItem};
use rtp::rtcp::sli::{Sli, SliEntry};
use rtp::rtcp::sr::SenderReport;
use rtp::rtcp::twcc::{Delta, Twcc, MAX_STATUSES};
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
fn twcc_encoding_is_capped_like_parsing() {
    let twcc = Twcc {
        statuses: vec![Delta::NotReceived; MAX_STATUSES + 1],
        ..Twcc::default()
    };
    assert_eq!(
        twcc.encode(),
        Err(too_large(
            "TWCC packet status count",
            MAX_STATUSES,
            MAX_STATUSES + 1
        ))
    );

    let full = Twcc {
        statuses: vec![Delta::NotReceived; MAX_STATUSES],
        ..Twcc::default()
    };
    let RtcpPacket::Twcc(parsed) = RtcpPacket::parse(&full.encode().unwrap()).unwrap() else {
        panic!("expected TWCC");
    };
    assert_eq!(parsed.statuses.len(), MAX_STATUSES);
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

#[test]
fn payload_type_above_127_is_rejected() {
    assert_eq!(
        RtpPacket::builder().payload_type(128).build(),
        Err(too_large("RTP payload type", 127, 128))
    );
    let packet = RtpPacket::builder().payload_type(127).build().unwrap();
    assert_eq!(packet.header().payload_type(), 127);

    let mut header = packet.header().clone();
    assert_eq!(
        header.set_payload_type(200),
        Err(too_large("RTP payload type", 127, 200))
    );
    assert_eq!(header.payload_type(), 127);
    assert_eq!(header.set_payload_type(96), Ok(()));
    assert_eq!(header.payload_type(), 96);
}

#[test]
fn sli_fields_must_fit_their_bit_widths() {
    let sli = |first, number, picture_id| Sli {
        sender_ssrc: 1,
        media_ssrc: 2,
        entries: vec![SliEntry {
            first,
            number,
            picture_id,
        }],
    };
    assert_eq!(
        sli(0x2000, 1, 1).encode(),
        Err(too_large("SLI first macroblock", 0x1FFF, 0x2000))
    );
    assert_eq!(
        sli(1, 0x2000, 1).encode(),
        Err(too_large("SLI macroblock count", 0x1FFF, 0x2000))
    );
    assert_eq!(
        sli(1, 1, 64).encode(),
        Err(too_large("SLI picture ID", 0x3F, 64))
    );
    let max = sli(0x1FFF, 0x1FFF, 0x3F);
    assert_eq!(
        RtcpPacket::parse(&max.encode().unwrap()).unwrap(),
        RtcpPacket::Sli(max)
    );
}

#[test]
fn cumulative_lost_must_fit_24_bits() {
    let block = |cumulative_lost| ReportBlock {
        cumulative_lost,
        ..ReportBlock::default()
    };
    let rr = ReceiverReport {
        ssrc: 1,
        reports: vec![block(0x0100_0000)],
    };
    assert_eq!(
        rr.encode(),
        Err(too_large(
            "RTCP report block cumulative lost",
            0x00FF_FFFF,
            0x0100_0000
        ))
    );
    let sr = SenderReport {
        reports: vec![block(0x0100_0000)],
        ..SenderReport::default()
    };
    assert!(sr.encode().is_err());
    let ok = ReceiverReport {
        ssrc: 1,
        reports: vec![block(0x00FF_FFFF)],
    };
    assert_eq!(
        RtcpPacket::parse(&ok.encode().unwrap()).unwrap(),
        RtcpPacket::ReceiverReport(ok)
    );
}
