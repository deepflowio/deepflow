use crate::{
    payload::{PaylaodIter, Payload},
    ringbuf::RingBuf,
    tcp_reassemble::{BufferData, TcpFragementMeta},
};

#[test]
fn test_payload_single() {
    let packets = [
        (
            TcpFragementMeta {
                seq: 1,
                payload_len: 2,
                is_parsed: false,
            },
            vec![0u8; 2],
        ),
        (
            TcpFragementMeta {
                seq: 3,
                payload_len: 3,
                is_parsed: false,
            },
            vec![1u8; 3],
        ),
        (
            TcpFragementMeta {
                seq: 6,
                payload_len: 4,
                is_parsed: false,
            },
            vec![2u8; 4],
        ),
    ];

    let packets2 = [
        (
            TcpFragementMeta {
                seq: 12,
                payload_len: 6,
                is_parsed: false,
            },
            vec![3u8; 6],
        ),
        (
            TcpFragementMeta {
                seq: 18,
                payload_len: 8,
                is_parsed: false,
            },
            vec![4u8; 8],
        ),
        (
            TcpFragementMeta {
                seq: 26,
                payload_len: 12,
                is_parsed: false,
            },
            vec![5u8; 12],
        ),
    ];

    let mut buf = BufferData {
        flow_id: 0,
        direction: 0,
        buf: RingBuf::new(64),
        tcp_meta: Vec::with_capacity(6),
        base_seq: None,
        max_frame: 6,
    };

    for (t, p) in packets.iter() {
        let _ = buf.reassemble(t.seq, p.as_slice());
    }

    for (t, p) in packets2.iter() {
        let _ = buf.reassemble(t.seq, p.as_slice());
    }

    assert_eq!(buf.tcp_meta.len(), 6);

    let (f, p) = buf.get_consequent_buffer().unwrap();
    let f_cp = Vec::from_iter(f.iter().map(|t| t.clone()));
    let mut payload_iter = PaylaodIter::new(Payload::SingleBuffer(p, f));
    let mut idx = 0;

    // test SingleBuffer
    while let Some(p) = payload_iter.peek(idx) {
        let mut payload = vec![];
        for i in 0..idx + 1 {
            payload.extend_from_slice(packets[i].1.as_slice());
        }

        assert_eq!(p, payload.as_slice());
        assert_eq!(packets[idx].0, f_cp.get(idx).unwrap().clone());
        idx += 1;
    }

    idx = 0;
    while let Some(p) = payload_iter.get() {
        let mut payload = vec![];
        for i in 0..idx + 1 {
            payload.extend_from_slice(packets[i].1.as_slice());
        }

        assert_eq!(p, payload.as_slice());
        assert_eq!(packets[idx].0, f_cp.get(idx).unwrap().clone());
        idx += 1;
        payload_iter.move_next();
    }

    // test MultiBuffer
    let p = buf.flush_all_buf();
    let mut payload_iter = PaylaodIter::new(Payload::MultiBuffer(p));

    idx = 0;
    while let Some(p) = payload_iter.peek(idx) {
        let mut payload = vec![];
        for i in 0..idx + 1 {
            payload.extend_from_slice(packets2[i].1.as_slice());
        }

        assert_eq!(p, payload);
        idx += 1;
    }

    idx = 1usize;
    while let Some(p) = payload_iter.get() {
        let mut payload = vec![];
        for i in 0..idx {
            payload.extend_from_slice(packets2[i].1.as_slice());
        }

        assert_eq!(p, payload);
        idx += 1;
        payload_iter.move_next();
    }
}

#[test]
fn test_skip_payload() {
    let packets = [
        (
            TcpFragementMeta {
                seq: 1,
                payload_len: 2,
                is_parsed: false,
            },
            vec![0u8; 2],
        ),
        (
            TcpFragementMeta {
                seq: 3,
                payload_len: 3,
                is_parsed: false,
            },
            vec![1u8; 3],
        ),
        (
            TcpFragementMeta {
                seq: 6,
                payload_len: 4,
                is_parsed: false,
            },
            vec![2u8; 4],
        ),
    ];

    let packets2 = [
        (
            TcpFragementMeta {
                seq: 12,
                payload_len: 6,
                is_parsed: false,
            },
            vec![3u8; 6],
        ),
        (
            TcpFragementMeta {
                seq: 18,
                payload_len: 8,
                is_parsed: false,
            },
            vec![4u8; 8],
        ),
        (
            TcpFragementMeta {
                seq: 26,
                payload_len: 12,
                is_parsed: false,
            },
            vec![5u8; 12],
        ),
    ];

    let mut buf = BufferData {
        flow_id: 0,
        direction: 0,
        buf: RingBuf::new(64),
        tcp_meta: Vec::with_capacity(6),
        base_seq: None,
        max_frame: 6,
    };

    for (t, p) in packets.iter() {
        let _ = buf.reassemble(t.seq, p.as_slice());
    }

    for (t, p) in packets2.iter() {
        let _ = buf.reassemble(t.seq, p.as_slice());
    }

    let (f, p) = buf.get_consequent_buffer().unwrap();
    let f_cp = Vec::from_iter(f.iter().map(|t| t.clone()));
    let mut payload_iter = PaylaodIter::new(Payload::SingleBuffer(p, f));
    let mut idx = 0;

    while let Some(p) = payload_iter.get() {
        assert_eq!(p, packets[idx].1.as_slice());
        payload_iter.move_next();
        payload_iter.skip_head_frame();
        idx += 1;
    }

    // test MultiBuffer

    let mut buf = BufferData {
        flow_id: 0,
        direction: 0,
        buf: RingBuf::new(64),
        tcp_meta: Vec::with_capacity(6),
        base_seq: None,
        max_frame: 6,
    };

    for (t, p) in packets.iter() {
        let _ = buf.reassemble(t.seq, p.as_slice());
    }

    for (t, p) in packets2.iter() {
        let _ = buf.reassemble(t.seq, p.as_slice());
    }

    let p = buf.flush_all_buf();
    let mut payload_iter = PaylaodIter::new(Payload::MultiBuffer(p));

    idx = 0;
    while let Some(p) = payload_iter.get() {
        if idx < 3 {
            assert_eq!(p, packets[idx].1.as_slice());
        } else {
            assert_eq!(p, packets2[idx - 3].1.as_slice());
        }
        payload_iter.move_next();
        payload_iter.skip_head_frame();
        idx += 1;
    }
}
