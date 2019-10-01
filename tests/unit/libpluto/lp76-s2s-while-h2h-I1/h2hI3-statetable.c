void h2h_insert_states(void);
struct state h2h_sa_1001;
struct state h2h_sa_1002;
struct connection h2h_conn_0;
/* SA #1001 @ 0x7ffff7f613d8 */
struct state h2h_sa_1001 = {
  .st_serialno = 1001,
  .st_clonedfrom = 0,
  .st_replaced = 0,
  .st_usage = 0,
  .st_ikev2 = 1,
  .st_ikev2_orig_initiator = 1,
  .st_ike_maj = 2,
  .st_ike_min = 0,
  .st_rekeytov2 = 0,
  .st_connection = &h2h_conn_0,
  .st_whack_sock = -1,
  .st_suspended_md = 0x0,
  .st_suspended_md_func = NULL,
  .st_suspended_md_line = 192,
  .st_oakley = {
    .encrypt = 3,
    .enckeylen = 192,
    .prf_hash = 1,
    .integ_hash = 1,
    .auth = 0,
    .xauth = 0,
    .groupnum = 14,
    .life_seconds = 0,
    .life_kilobytes = 0,
    .encrypter = NULL,
    .prf_hasher = NULL,
    .integ_hasher = NULL,
    .group = oakley_group+64,
    .ei = 0x0
  },
  .st_ah = {
    .present = 0,
    .attrs = {
      .transattrs = {
        .encrypt = 0,
        .enckeylen = 0,
        .prf_hash = 0,
        .integ_hash = 0,
        .auth = 0,
        .xauth = 0,
        .groupnum = 0,
        .life_seconds = 0,
        .life_kilobytes = 0,
        .encrypter = 0x0,
        .prf_hasher = 0x0,
        .integ_hasher = 0x0,
        .group = 0x0,
        .ei = 0x0
      },
      .spi = 0,
      .life_seconds = 0,
      .life_kilobytes = 0,
      .encapsulation = 0
    },
    .our_spi = 0,
    .our_spi_in_kernel = 0,
    .keymat_len = 0,
    .our_keymat = 0x0,
    .peer_keymat = 0x0,
    .our_bytes = 0,
    .peer_bytes = 0,
    .our_lastused = 0,
    .peer_lastused = 0
  },
  .st_esp = {
    .present = 0,
    .attrs = {
      .transattrs = {
        .encrypt = 0,
        .enckeylen = 0,
        .prf_hash = 0,
        .integ_hash = 0,
        .auth = 0,
        .xauth = 0,
        .groupnum = 0,
        .life_seconds = 0,
        .life_kilobytes = 0,
        .encrypter = 0x0,
        .prf_hasher = 0x0,
        .integ_hasher = 0x0,
        .group = 0x0,
        .ei = 0x0
      },
      .spi = 0,
      .life_seconds = 0,
      .life_kilobytes = 0,
      .encapsulation = 0
    },
    .our_spi = 0,
    .our_spi_in_kernel = 0,
    .keymat_len = 0,
    .our_keymat = 0x0,
    .peer_keymat = 0x0,
    .our_bytes = 0,
    .peer_bytes = 0,
    .our_lastused = 0,
    .peer_lastused = 0
  },
  .st_ipcomp = {
    .present = 0,
    .attrs = {
      .transattrs = {
        .encrypt = 0,
        .enckeylen = 0,
        .prf_hash = 0,
        .integ_hash = 0,
        .auth = 0,
        .xauth = 0,
        .groupnum = 0,
        .life_seconds = 0,
        .life_kilobytes = 0,
        .encrypter = 0x0,
        .prf_hasher = 0x0,
        .integ_hasher = 0x0,
        .group = 0x0,
        .ei = 0x0
      },
      .spi = 0,
      .life_seconds = 0,
      .life_kilobytes = 0,
      .encapsulation = 0
    },
    .our_spi = 0,
    .our_spi_in_kernel = 0,
    .keymat_len = 0,
    .our_keymat = 0x0,
    .peer_keymat = 0x0,
    .our_bytes = 0,
    .peer_bytes = 0,
    .our_lastused = 0,
    .peer_lastused = 0
  },
  .st_tunnel_in_spi = 0,
  .st_tunnel_out_spi = 0,
  .st_ref = 0,
  .st_refhim = 0,
  .st_outbound_done = 0,
  .st_pfs_group = 0x0,
  .st_doi = 0,
  .st_situation = 0,
  .st_policy = 4412407810,
  .st_remoteaddr = {
    .u = {
      .v4 = {
        .sin_family = 2,
        .sin_port = 0,
        .sin_addr = {
          .s_addr = 133092740
        },
        .sin_zero = "\000\000\000\000\000\000\000"
      },
      .v6 = {
        .sin6_family = 2,
        .sin6_port = 0,
        .sin6_flowinfo = 133092740,
        .sin6_addr = {
          .__in6_u = {
            .__u6_addr8 = {'\000',},
            .__u6_addr16 = {0, 0, 0, 0, 0, 0, 0, 0},
            .__u6_addr32 = {0, 0, 0, 0}
          }
        },
        .sin6_scope_id = 0
      }
    }
  },
  .st_remoteport = 500,
  .st_interface = &parker_if1,
  .st_localaddr = {
    .u = {
      .v4 = {
        .sin_family = 2,
        .sin_port = 62465,
        .sin_addr = {
          .s_addr = 16885952
        },
        .sin_zero = "\000\000\000\000\000\000\000"
      },
      .v6 = {
        .sin6_family = 2,
        .sin6_port = 62465,
        .sin6_flowinfo = 16885952,
        .sin6_addr = {
          .__in6_u = {
            .__u6_addr8 = {'\000',},
            .__u6_addr16 = {0, 0, 0, 0, 0, 0, 0, 0},
            .__u6_addr32 = {0, 0, 0, 0}
          }
        },
        .sin6_scope_id = 0
      }
    }
  },
  .st_localport = 500,
  .st_sadb = NULL,
  .st_msgid = 0,
  .st_reserve_msgid = 0,
  .st_msgid_phase15 = 0,
  .st_msgid_phase15b = 0,
  .st_used_msgids = 0x0,
  .ikev2 = {
    .st_peer_id = {
      .has_wildcards = 0,
      .kind = 0,
      .ip_addr = {
        .u = {
          .v4 = {
            .sin_family = 0,
            .sin_port = 0,
            .sin_addr = {
              .s_addr = 0
            },
            .sin_zero = "\000\000\000\000\000\000\000"
          },
          .v6 = {
            .sin6_family = 0,
            .sin6_port = 0,
            .sin6_flowinfo = 0,
            .sin6_addr = {
              .__in6_u = {
                .__u6_addr8 = {'\000',},
                .__u6_addr16 = {0, 0, 0, 0, 0, 0, 0, 0},
                .__u6_addr32 = {0, 0, 0, 0}
              }
            },
            .sin6_scope_id = 0
          }
        }
      },
      .name = {
        .ptr = 0x0,
        .len = 0
      }
    },
    .st_peer_buf = {'\000',},
    .st_local_id = {
      .has_wildcards = 0,
      .kind = 0,
      .ip_addr = {
        .u = {
          .v4 = {
            .sin_family = 0,
            .sin_port = 0,
            .sin_addr = {
              .s_addr = 0
            },
            .sin_zero = "\000\000\000\000\000\000\000"
          },
          .v6 = {
            .sin6_family = 0,
            .sin6_port = 0,
            .sin6_flowinfo = 0,
            .sin6_addr = {
              .__in6_u = {
                .__u6_addr8 = {'\000',},
                .__u6_addr16 = {0, 0, 0, 0, 0, 0, 0, 0},
                .__u6_addr32 = {0, 0, 0, 0}
              }
            },
            .sin6_scope_id = 0
          }
        }
      },
      .name = {
        .ptr = 0x0,
        .len = 0
      }
    },
    .st_local_buf = {'\000',}
  },
  .st_msg_retransmitted = 0,
  .st_msg_badmsgid_recv = 0,
  .st_msgid_lastack = 1,
  .st_msgid_nextuse = 2,
  .st_msgid_lastrecv = 4294967295,
  .st_sa_logged = 1,
  .st_gi = {
    .ptr = "E\247?\373% w\263E\n\344\221\246\257Id\231\327\231\b\350\206\037\321)\307hd\253)\303\373\255G\232\320k5\b\355\320\234Y\373\350\270\036\330\v\246\203\220\312Js\366\\\301\237\255\062Wp\343e'\232\217i-R\354\341B\274\333\200\213\020j\002q\376\025)\036\372\212\346!\211\204\320\335r\031\t\034&\001\304>\273\301\266\315\312\374\326\367\252\r\206b!\344\036\206\212t[\006\325,\031'U\312\273^\035 \340\343$y\233\331e\247PWH\261Z\320q\242`\357\024ui\335\024\032\t\210m\303\262}\365\030\275\301\063\035\260}\266\334+\036\241\230\006\273\252\304\244i\263\304\360N\b\363\356s\205AOZ\335\323U\341\354\242\341\227\373/\362\260o\274\374_k\302:2\346F\341\337Bp\003\034\016\251\035\313\340u\312\335E\255\327\027\371\002\357\340\371x\321\036\202\217\302\267\252%\031o/\bM+\337\334",
    .len = 256
  },
  .st_icookie = "\200\001\002\003\004\005\006\a",
  .st_ni = {
    .ptr = "\200\001\002\003\004\005\006\a\b\t\n\v\f\r\016\017",
    .len = 16
  },
  .st_gr = {
    .ptr = "%\232N\231\215\254\331{}\255\233*\275\070\004",
    .len = 256
  },
  .st_rcookie = "\336\274X:\217@\320\317",
  .st_nr = {
    .ptr = "",
    .len = 16
  },
  .st_dcookie = {
    .ptr = 0x0,
    .len = 0
  },
  .st_tpacket = {
    .ptr = "\200\001\002\003\004\005\006\a\336\274X:\217@\320\317. #\b",
    .len = 476
  },
  .st_firstpacket_me = {
    .ptr = "\200\001\002\003\004\005\006\a",
    .len = 892
  },
  .st_firstpacket_him = {
    .ptr = "\200\001\002\003\004\005\006\a\336\274X:\217@\320\317! \" ",
    .len = 428
  },
  .sec_ctx = 0x0,
  .st_myuserprotoid = 0,
  .st_myuserport = 0,
  .st_rpacket = {
    .ptr = 0x0,
    .len = 0
  },
  .st_peeruserprotoid = 0,
  .st_peeruserport = 0,
  .st_peeridentity_protocol = 0,
  .st_peeridentity_port = 0,
  .st_our_keyid = "fakesig1\000",
  .st_their_keyid = "fakecheck",
  .st_sec_in_use = 1,
  .st_sec = {
    ._mp_alloc = 5,
    ._mp_size = 4,
    ._mp_d = NULL
  },
  .st_sec_chunk = {
    .ptr = "\200\001\002\003\004\005\006\a\b\t\n\v\f\r\016\017\020\021\022\023\024\025\026\027\030\031\032\033\034\035\036\037",
    .len = 32
  },
  .st_shared = {
    .ptr = "\035d\251\311\213\177p\364\n\237\215-*\243l\364X\255\313q\212dA)\222\t{V\366j{\361W\300E5\246\323\332\233\216\361 \255\021\312\004:V\342\360`u9\026\264\030\066\357X\302/\006\310N\030\022:\025\006\345\363\346\062\002\367\215\327\364\356B\311\252\320\064D\266\234\371\215~\367\221+\303\247\275w\346\037V\250\220\373\277\377\066\206\304\241\263}\271\326\b\333\002\260\254^\355\336\263\266\323\027r\201\r\255\215\307\201\035\372L\311%\237]\036\t-I\326\376\235\207\315\257\027MD(\317\251S\276\267i\264\247\355\261\307VH\344\305Bd\223T\247B\323Y\220\242\310\270v\t\355\250\262\204b\277\202\236' \274\t\017 \372=7\v\370S\027\271\313\223\256\002\337\340\340\224w\246\205\333\030\254\357\202\224\305:\363)\351E\001\246v\360uF\363iCu(\236+]XZ\360A\032\b\362u\255\305Kl\221\n",
    .len = 256
  },
  .st_import = pcim_demand_crypto,
  .st_peer_pubkey = 0x0,
  .st_state = STATE_PARENT_I3,
  .st_retransmit = 0,
  .st_try = 0,
  .st_margin = 0,
  .st_outbound_count = 1,
  .st_outbound_time = 1528160967,
  .st_calculating = 0,
  .st_p1isa = {
    .ptr = "\"",
    .len = 508
  },
  .st_skeyseed = {
    .ptr = 0x0,
    .len = 0
  },
  .st_skey_d = {
    .ptr = "H\210\003y\262#\316\253o\374\016\306\312\212It",
    .len = 16
  },
  .st_skey_ai = {
    .ptr = "\364\301\001\307!\030\317\061\324h/h\271\242\234\a",
    .len = 16
  },
  .st_skey_ar = {
    .ptr = "\347\065CQ\351\240\201\303e\262v\032\305\370\025\352",
    .len = 16
  },
  .st_skey_ei = {
    .ptr = "\r\b\\\260\333>\205lMGE\314\037\365\311'OX\b'\360<\032\255",
    .len = 24
  },
  .st_skey_er = {
    .ptr = "\217\001FJk\032z\257\213\212\226\234\210\363\314\216\370*\226\315r\030\374\021",
    .len = 24
  },
  .st_skey_pi = {
    .ptr = "\330S\001\355\060\216\224\336\203\322\062E\233f\034\226",
    .len = 16
  },
  .st_skey_pr = {
    .ptr = "\226@\033\177*\224\002\374d\260\276\374\336\326\326\216",
    .len = 16
  },
  .st_childsa = 0x0,
  .st_ts_this = {
    .ts_type = 0,
    .ipprotoid = 0,
    .startport = 0,
    .endport = 0,
    .low = {
      .u = {
        .v4 = {
          .sin_family = 0,
          .sin_port = 0,
          .sin_addr = {
            .s_addr = 0
          },
          .sin_zero = "\000\000\000\000\000\000\000"
        },
        .v6 = {
          .sin6_family = 0,
          .sin6_port = 0,
          .sin6_flowinfo = 0,
          .sin6_addr = {
            .__in6_u = {
              .__u6_addr8 = {'\000',},
              .__u6_addr16 = {0, 0, 0, 0, 0, 0, 0, 0},
              .__u6_addr32 = {0, 0, 0, 0}
            }
          },
          .sin6_scope_id = 0
        }
      }
    },
    .high = {
      .u = {
        .v4 = {
          .sin_family = 0,
          .sin_port = 0,
          .sin_addr = {
            .s_addr = 0
          },
          .sin_zero = "\000\000\000\000\000\000\000"
        },
        .v6 = {
          .sin6_family = 0,
          .sin6_port = 0,
          .sin6_flowinfo = 0,
          .sin6_addr = {
            .__in6_u = {
              .__u6_addr8 = {'\000',},
              .__u6_addr16 = {0, 0, 0, 0, 0, 0, 0, 0},
              .__u6_addr32 = {0, 0, 0, 0}
            }
          },
          .sin6_scope_id = 0
        }
      }
    }
  },
  .st_ts_that = {
    .ts_type = 0,
    .ipprotoid = 0,
    .startport = 0,
    .endport = 0,
    .low = {
      .u = {
        .v4 = {
          .sin_family = 0,
          .sin_port = 0,
          .sin_addr = {
            .s_addr = 0
          },
          .sin_zero = "\000\000\000\000\000\000\000"
        },
        .v6 = {
          .sin6_family = 0,
          .sin6_port = 0,
          .sin6_flowinfo = 0,
          .sin6_addr = {
            .__in6_u = {
              .__u6_addr8 = {'\000',},
              .__u6_addr16 = {0, 0, 0, 0, 0, 0, 0, 0},
              .__u6_addr32 = {0, 0, 0, 0}
            }
          },
          .sin6_scope_id = 0
        }
      }
    },
    .high = {
      .u = {
        .v4 = {
          .sin_family = 0,
          .sin_port = 0,
          .sin_addr = {
            .s_addr = 0
          },
          .sin_zero = "\000\000\000\000\000\000\000"
        },
        .v6 = {
          .sin6_family = 0,
          .sin6_port = 0,
          .sin6_flowinfo = 0,
          .sin6_addr = {
            .__in6_u = {
              .__u6_addr8 = {'\000',},
              .__u6_addr16 = {0, 0, 0, 0, 0, 0, 0, 0},
              .__u6_addr32 = {0, 0, 0, 0}
            }
          },
          .sin6_scope_id = 0
        }
      }
    }
  },
  .st_iv = {'\000',},
  .st_old_iv = {'\000',},
  .st_new_iv = {'\000',},
  .st_ph1_iv = {'\000',},
  .st_iv_len = 0,
  .st_old_iv_len = 0,
  .st_new_iv_len = 0,
  .st_ph1_iv_len = 0,
  .st_enc_key = {
    .ptr = 0x0,
    .len = 0
  },
  .st_event = 0x0,
  .st_hashchain_next = 0x0,
  .st_hashchain_prev = &h2h_sa_1002,
  .hidden_variables = {
    .st_malformed_received = 0,
    .st_malformed_sent = 0,
    .st_xauth_client_done = 0,
    .st_xauth_client_attempt = 0,
    .st_modecfg_server_done = 0,
    .st_modecfg_vars_set = 0,
    .st_got_certrequest = 0,
    .st_modecfg_started = 0,
    .st_skeyid_calculated = 1,
    .st_dpd = 0,
    .st_dpd_local = 0,
    .st_logged_p1algos = 1,
    .st_nat_traversal = 0,
    .st_nat_oa = {
      .u = {
        .v4 = {
          .sin_family = 2,
          .sin_port = 0,
          .sin_addr = {
            .s_addr = 0
          },
          .sin_zero = "\000\000\000\000\000\000\000"
        },
        .v6 = {
          .sin6_family = 2,
          .sin6_port = 0,
          .sin6_flowinfo = 0,
          .sin6_addr = {
            .__in6_u = {
              .__u6_addr8 = {'\000',},
              .__u6_addr16 = {0, 0, 0, 0, 0, 0, 0, 0},
              .__u6_addr32 = {0, 0, 0, 0}
            }
          },
          .sin6_scope_id = 0
        }
      }
    },
    .st_natd = {
      .u = {
        .v4 = {
          .sin_family = 2,
          .sin_port = 0,
          .sin_addr = {
            .s_addr = 0
          },
          .sin_zero = "\000\000\000\000\000\000\000"
        },
        .v6 = {
          .sin6_family = 2,
          .sin6_port = 0,
          .sin6_flowinfo = 0,
          .sin6_addr = {
            .__in6_u = {
              .__u6_addr8 = {'\000',},
              .__u6_addr16 = {0, 0, 0, 0, 0, 0, 0, 0},
              .__u6_addr32 = {0, 0, 0, 0}
            }
          },
          .sin6_scope_id = 0
        }
      }
    }
  },
  .st_xauth_username = {'\000',},
  .st_xauth_password = {
    .ptr = 0x0,
    .len = 0
  },
  .st_last_dpd = 0,
  .st_dpd_seqno = 0,
  .st_dpd_expectseqno = 0,
  .st_dpd_peerseqno = 0,
  .st_dpd_event = 0x0,
  .st_seen_vendorid = 0,
  .quirks = {
    .xauth_ack_msgid = 0,
    .modecfg_pull_mode = 0,
    .nat_traversal_vid = 0,
    .xauth_vid = 0
  }
};
/* SA #1002 @ 0x7ffff70c13d8 */
struct state h2h_sa_1002 = {
  .st_serialno = 1002,
  .st_clonedfrom = 1001,
  .st_replaced = 0,
  .st_usage = 0,
  .st_ikev2 = 1,
  .st_ikev2_orig_initiator = 1,
  .st_ike_maj = 2,
  .st_ike_min = 0,
  .st_rekeytov2 = 0,
  .st_connection = &h2h_conn_0,
  .st_whack_sock = -1,
  .st_suspended_md = 0x0,
  .st_suspended_md_func = 0x0,
  .st_suspended_md_line = 0,
  .st_oakley = {
    .encrypt = 3,
    .enckeylen = 192,
    .prf_hash = 1,
    .integ_hash = 1,
    .auth = 0,
    .xauth = 0,
    .groupnum = 14,
    .life_seconds = 0,
    .life_kilobytes = 0,
    .encrypter = NULL,
    .prf_hasher = NULL,
    .integ_hasher = NULL,
    .group = oakley_group+64,
    .ei = 0x0
  },
  .st_ah = {
    .present = 0,
    .attrs = {
      .transattrs = {
        .encrypt = 0,
        .enckeylen = 0,
        .prf_hash = 0,
        .integ_hash = 0,
        .auth = 0,
        .xauth = 0,
        .groupnum = 0,
        .life_seconds = 0,
        .life_kilobytes = 0,
        .encrypter = 0x0,
        .prf_hasher = 0x0,
        .integ_hasher = 0x0,
        .group = 0x0,
        .ei = 0x0
      },
      .spi = 0,
      .life_seconds = 0,
      .life_kilobytes = 0,
      .encapsulation = 0
    },
    .our_spi = 0,
    .our_spi_in_kernel = 0,
    .keymat_len = 0,
    .our_keymat = 0x0,
    .peer_keymat = 0x0,
    .our_bytes = 0,
    .peer_bytes = 0,
    .our_lastused = 0,
    .peer_lastused = 0
  },
  .st_esp = {
    .present = 1,
    .attrs = {
      .transattrs = {
        .encrypt = 12,
        .enckeylen = 128,
        .prf_hash = 0,
        .integ_hash = 2,
        .auth = 0,
        .xauth = 0,
        .groupnum = 0,
        .life_seconds = 0,
        .life_kilobytes = 0,
        .encrypter = NULL,
        .prf_hasher = 0x0,
        .integ_hasher = 0x0,
        .group = 0x0,
      },
      .spi = 2018915346,
      .life_seconds = 0,
      .life_kilobytes = 0,
      .encapsulation = 1
    },
    .our_spi = 2018915346,
    .our_spi_in_kernel = 0,
    .keymat_len = 36,
    .our_keymat = "\343\263\375\305OX\262Y\251@\003y\210D}\352\353\022c\276\231\066\343\221k\274`\330q\226\v\310\247O\024;",
    .peer_keymat = "\347\361\v\322\220>\031\366\005\236\363K\032\301\261\236\316\225\024\061\311\037\031\227\303\336`\243\027\364a\003\201\370\247\223",
    .our_bytes = 0,
    .peer_bytes = 0,
    .our_lastused = 0,
    .peer_lastused = 0
  },
  .st_ipcomp = {
    .present = 0,
    .attrs = {
      .transattrs = {
        .encrypt = 0,
        .enckeylen = 0,
        .prf_hash = 0,
        .integ_hash = 0,
        .auth = 0,
        .xauth = 0,
        .groupnum = 0,
        .life_seconds = 0,
        .life_kilobytes = 0,
        .encrypter = 0x0,
        .prf_hasher = 0x0,
        .integ_hasher = 0x0,
        .group = 0x0,
      },
      .spi = 0,
      .life_seconds = 0,
      .life_kilobytes = 0,
      .encapsulation = 0
    },
    .our_spi = 0,
    .our_spi_in_kernel = 0,
    .keymat_len = 0,
    .our_keymat = 0x0,
    .peer_keymat = 0x0,
    .our_bytes = 0,
    .peer_bytes = 0,
    .our_lastused = 0,
    .peer_lastused = 0
  },
  .st_tunnel_in_spi = 0,
  .st_tunnel_out_spi = 0,
  .st_ref = 0,
  .st_refhim = 0,
  .st_outbound_done = 0,
  .st_pfs_group = 0x0,
  .st_doi = 0,
  .st_situation = 0,
  .st_policy = 100,
  .st_remoteaddr = {
    .u = {
      .v4 = {
        .sin_family = 2,
        .sin_port = 0,
        .sin_addr = {
          .s_addr = 133092740
        },
        .sin_zero = "\000\000\000\000\000\000\000"
      },
      .v6 = {
        .sin6_family = 2,
        .sin6_port = 0,
        .sin6_flowinfo = 133092740,
        .sin6_addr = {
          .__in6_u = {
            .__u6_addr8 = {'\000',},
            .__u6_addr16 = {0, 0, 0, 0, 0, 0, 0, 0},
            .__u6_addr32 = {0, 0, 0, 0}
          }
        },
        .sin6_scope_id = 0
      }
    }
  },
  .st_remoteport = 500,
  .st_interface = &parker_if1,
  .st_localaddr = {
    .u = {
      .v4 = {
        .sin_family = 2,
        .sin_port = 62465,
        .sin_addr = {
          .s_addr = 16885952
        },
        .sin_zero = "\000\000\000\000\000\000\000"
      },
      .v6 = {
        .sin6_family = 2,
        .sin6_port = 62465,
        .sin6_flowinfo = 16885952,
        .sin6_addr = {
          .__in6_u = {
            .__u6_addr8 = {'\000',},
            .__u6_addr16 = {0, 0, 0, 0, 0, 0, 0, 0},
            .__u6_addr32 = {0, 0, 0, 0}
          }
        },
        .sin6_scope_id = 0
      }
    }
  },
  .st_localport = 500,
  .st_sadb = 0x0,
  .st_msgid = 1,
  .st_reserve_msgid = 0,
  .st_msgid_phase15 = 0,
  .st_msgid_phase15b = 0,
  .st_used_msgids = 0x0,
  .ikev2 = {
    .st_peer_id = {
      .has_wildcards = 0,
      .kind = 1,
      .ip_addr = {
        .u = {
          .v4 = {
            .sin_family = 2,
            .sin_port = 0,
            .sin_addr = {
              .s_addr = 133092740
            },
            .sin_zero = "\000\000\000\000\000\000\000"
          },
          .v6 = {
            .sin6_family = 2,
            .sin6_port = 0,
            .sin6_flowinfo = 133092740,
            .sin6_addr = {
              .__in6_u = {
                .__u6_addr8 = {'\000',},
                .__u6_addr16 = {0, 0, 0, 0, 0, 0, 0, 0},
                .__u6_addr32 = {0, 0, 0, 0}
              }
            },
            .sin6_scope_id = 0
          }
        }
      },
      .name = {
        .ptr = 0x0,
        .len = 0
      }
    },
    .st_peer_buf = "132.213.238.7", {'\000',},
    .st_local_id = {
      .has_wildcards = 0,
      .kind = 0,
      .ip_addr = {
        .u = {
          .v4 = {
            .sin_family = 0,
            .sin_port = 0,
            .sin_addr = {
              .s_addr = 0
            },
            .sin_zero = "\000\000\000\000\000\000\000"
          },
          .v6 = {
            .sin6_family = 0,
            .sin6_port = 0,
            .sin6_flowinfo = 0,
            .sin6_addr = {
              .__in6_u = {
                .__u6_addr8 = {'\000',},
                .__u6_addr16 = {0, 0, 0, 0, 0, 0, 0, 0},
                .__u6_addr32 = {0, 0, 0, 0}
              }
            },
            .sin6_scope_id = 0
          }
        }
      },
      .name = {
        .ptr = 0x0,
        .len = 0
      }
    },
    .st_local_buf = {'\000',}
  },
  .st_msg_retransmitted = 0,
  .st_msg_badmsgid_recv = 0,
  .st_msgid_lastack = 4294967295,
  .st_msgid_nextuse = 0,
  .st_msgid_lastrecv = 4294967295,
  .st_sa_logged = 0,
  .st_gi = {
    .ptr = 0x0,
    .len = 0
  },
  .st_icookie = "\200\001\002\003\004\005\006\a",
  .st_ni = {
    .ptr = "\200\001\002\003\004\005\006\a\b\t\n\v\f\r\016\017",
    .len = 16
  },
  .st_gr = {
    .ptr = 0x0,
    .len = 0
  },
  .st_rcookie = "\336\274X:\217@\320\317",
  .st_nr = {
    .ptr = "",
    .len = 16
  },
  .st_dcookie = {
    .ptr = 0x0,
    .len = 0
  },
  .st_tpacket = {
    .ptr = "\200\001\002\003\004\005\006\a\336\274X:\217@\320\317. #\b",
    .len = 476
  },
  .st_firstpacket_me = {
    .ptr = 0x0,
    .len = 0
  },
  .st_firstpacket_him = {
    .ptr = 0x0,
    .len = 0
  },
  .sec_ctx = 0x0,
  .st_myuserprotoid = 0,
  .st_myuserport = 0,
  .st_rpacket = {
    .ptr = 0x0,
    .len = 0
  },
  .st_peeruserprotoid = 0,
  .st_peeruserport = 0,
  .st_peeridentity_protocol = 0,
  .st_peeridentity_port = 0,
  .st_our_keyid = "\000\000\000\000\000\000\000\000\000",
  .st_their_keyid = "\000\000\000\000\000\000\000\000\000",
  .st_sec_in_use = 0,
  .st_sec = {
    ._mp_alloc = 0,
    ._mp_size = 0,
    ._mp_d = 0x0
  },
  .st_sec_chunk = {
    .ptr = 0x0,
    .len = 0
  },
  .st_shared = {
    .ptr = 0x0,
    .len = 0
  },
  .st_import = pcim_demand_crypto,
  .st_peer_pubkey = 0x0,
  .st_state = STATE_CHILD_C1_KEYED,
  .st_retransmit = 0,
  .st_try = 0,
  .st_margin = 331,
  .st_outbound_count = 0,
  .st_outbound_time = 0,
  .st_calculating = 0,
  .st_p1isa = {
    .ptr = 0x0,
    .len = 0
  },
  .st_skeyseed = {
    .ptr = "",
    .len = 0
  },
  .st_skey_d = {
    .ptr = "H\210\003y\262#\316\253o\374\016\306\312\212It",
    .len = 16
  },
  .st_skey_ai = {
    .ptr = "\364\301\001\307!\030\317\061\324h/h\271\242\234\a",
    .len = 16
  },
  .st_skey_ar = {
    .ptr = "\347\065CQ\351\240\201\303e\262v\032\305\370\025\352",
    .len = 16
  },
  .st_skey_ei = {
    .ptr = "\r\b\\\260\333>\205lMGE\314\037\365\311'OX\b'\360<\032\255",
    .len = 24
  },
  .st_skey_er = {
    .ptr = "\217\001FJk\032z\257\213\212\226\234\210\363\314\216\370*\226\315r\030\374\021",
    .len = 24
  },
  .st_skey_pi = {
    .ptr = "\330S\001\355\060\216\224\336\203\322\062E\233f\034\226",
    .len = 16
  },
  .st_skey_pr = {
    .ptr = "\226@\033\177*\224\002\374d\260\276\374\336\326\326\216",
    .len = 16
  },
  .st_childsa = &h2h_conn_0,
  .st_ts_this = {
    .ts_type = 7,
    .ipprotoid = 0,
    .startport = 0,
    .endport = 65535,
    .low = {
      .u = {
        .v4 = {
          .sin_family = 2,
          .sin_port = 0,
          .sin_addr = {
            .s_addr = 16885952
          },
          .sin_zero = "\000\000\000\000\000\000\000"
        },
        .v6 = {
          .sin6_family = 2,
          .sin6_port = 0,
          .sin6_flowinfo = 16885952,
          .sin6_addr = {
            .__in6_u = {
              .__u6_addr8 = {'\000',},
              .__u6_addr16 = {0, 0, 0, 0, 0, 0, 0, 0},
              .__u6_addr32 = {0, 0, 0, 0}
            }
          },
          .sin6_scope_id = 0
        }
      }
    },
    .high = {
      .u = {
        .v4 = {
          .sin_family = 2,
          .sin_port = 0,
          .sin_addr = {
            .s_addr = 16885952
          },
          .sin_zero = "\000\000\000\000\000\000\000"
        },
        .v6 = {
          .sin6_family = 2,
          .sin6_port = 0,
          .sin6_flowinfo = 16885952,
          .sin6_addr = {
            .__in6_u = {
              .__u6_addr8 = {'\000',},
              .__u6_addr16 = {0, 0, 0, 0, 0, 0, 0, 0},
              .__u6_addr32 = {0, 0, 0, 0}
            }
          },
          .sin6_scope_id = 0
        }
      }
    }
  },
  .st_ts_that = {
    .ts_type = 7,
    .ipprotoid = 0,
    .startport = 0,
    .endport = 65535,
    .low = {
      .u = {
        .v4 = {
          .sin_family = 2,
          .sin_port = 0,
          .sin_addr = {
            .s_addr = 133092740
          },
          .sin_zero = "\000\000\000\000\000\000\000"
        },
        .v6 = {
          .sin6_family = 2,
          .sin6_port = 0,
          .sin6_flowinfo = 133092740,
          .sin6_addr = {
            .__in6_u = {
              .__u6_addr8 = {'\000',},
              .__u6_addr16 = {0, 0, 0, 0, 0, 0, 0, 0},
              .__u6_addr32 = {0, 0, 0, 0}
            }
          },
          .sin6_scope_id = 0
        }
      }
    },
    .high = {
      .u = {
        .v4 = {
          .sin_family = 2,
          .sin_port = 0,
          .sin_addr = {
            .s_addr = 133092740
          },
          .sin_zero = "\000\000\000\000\000\000\000"
        },
        .v6 = {
          .sin6_family = 2,
          .sin6_port = 0,
          .sin6_flowinfo = 133092740,
          .sin6_addr = {
            .__in6_u = {
              .__u6_addr8 = {'\000',},
              .__u6_addr16 = {0, 0, 0, 0, 0, 0, 0, 0},
              .__u6_addr32 = {0, 0, 0, 0}
            }
          },
          .sin6_scope_id = 0
        }
      }
    }
  },
  .st_iv = {'\000',},
  .st_old_iv = {'\000',},
  .st_new_iv = {'\000',},
  .st_ph1_iv = {'\000',},
  .st_iv_len = 0,
  .st_old_iv_len = 0,
  .st_new_iv_len = 0,
  .st_ph1_iv_len = 0,
  .st_enc_key = {
    .ptr = "",
    .len = 0
  },
  .st_event = 0x0,
  .st_hashchain_next = &h2h_sa_1001,
  .st_hashchain_prev = 0x0,
  .hidden_variables = {
    .st_malformed_received = 0,
    .st_malformed_sent = 0,
    .st_xauth_client_done = 0,
    .st_xauth_client_attempt = 0,
    .st_modecfg_server_done = 0,
    .st_modecfg_vars_set = 0,
    .st_got_certrequest = 0,
    .st_modecfg_started = 0,
    .st_skeyid_calculated = 1,
    .st_dpd = 0,
    .st_dpd_local = 0,
    .st_logged_p1algos = 0,
    .st_nat_traversal = 0,
    .st_nat_oa = {
      .u = {
        .v4 = {
          .sin_family = 2,
          .sin_port = 0,
          .sin_addr = {
            .s_addr = 0
          },
          .sin_zero = "\000\000\000\000\000\000\000"
        },
        .v6 = {
          .sin6_family = 2,
          .sin6_port = 0,
          .sin6_flowinfo = 0,
          .sin6_addr = {
            .__in6_u = {
              .__u6_addr8 = {'\000',},
              .__u6_addr16 = {0, 0, 0, 0, 0, 0, 0, 0},
              .__u6_addr32 = {0, 0, 0, 0}
            }
          },
          .sin6_scope_id = 0
        }
      }
    },
    .st_natd = {
      .u = {
        .v4 = {
          .sin_family = 2,
          .sin_port = 0,
          .sin_addr = {
            .s_addr = 0
          },
          .sin_zero = "\000\000\000\000\000\000\000"
        },
        .v6 = {
          .sin6_family = 2,
          .sin6_port = 0,
          .sin6_flowinfo = 0,
          .sin6_addr = {
            .__in6_u = {
              .__u6_addr8 = {'\000',},
              .__u6_addr16 = {0, 0, 0, 0, 0, 0, 0, 0},
              .__u6_addr32 = {0, 0, 0, 0}
            }
          },
          .sin6_scope_id = 0
        }
      }
    }
  },
  .st_xauth_username = {'\000',},
  .st_xauth_password = {
    .ptr = 0x0,
    .len = 0
  },
  .st_last_dpd = 0,
  .st_dpd_seqno = 0,
  .st_dpd_expectseqno = 0,
  .st_dpd_peerseqno = 0,
  .st_dpd_event = 0x0,
  .st_seen_vendorid = 0,
  .quirks = {
    .xauth_ack_msgid = 0,
    .modecfg_pull_mode = 0,
    .nat_traversal_vid = 0,
    .xauth_vid = 0
  }
};
/* CONN @ 0x7ffff7f55b00 */
struct connection h2h_conn_0 = {
  .name = "alttunnel",
  .connalias = 0x0,
  .policy = 4412407910,
  .sa_ike_life_seconds = 3600,
  .sa_ipsec_life_seconds = 1200,
  .sa_rekey_margin = 180,
  .sa_rekey_fuzz = 100,
  .sa_keying_tries = 1,
  .dpd_delay = 0,
  .dpd_timeout = 0,
  .dpd_action = DPD_ACTION_CLEAR,
  .remotepeertype = NON_CISCO,
  .sha2_truncbug = 0,
  .nmconfigured = 0,
  .loopback = 0,
  .labeled_ipsec = 0,
  .policy_label = 0x0,
  .forceencaps = 0,
  .log_file_name = 0x0,
  .log_file = 0x0,
  .log_link = {
    .cqe_next = 0x0,
    .cqe_prev = 0x0
  },
  .log_file_err = 0,
  .spd = {
    .next = 0x0,
    .this = {
      .id = {
        .has_wildcards = 0,
        .kind = 1,
        .ip_addr = {
          .u = {
            .v4 = {
              .sin_family = 2,
              .sin_port = 0,
              .sin_addr = {
                .s_addr = 16885952
              },
              .sin_zero = "\000\000\000\000\000\000\000"
            },
            .v6 = {
              .sin6_family = 2,
              .sin6_port = 0,
              .sin6_flowinfo = 16885952,
              .sin6_addr = {
                .__in6_u = {
                  .__u6_addr8 = {'\000',},
                  .__u6_addr16 = {0, 0, 0, 0, 0, 0, 0, 0},
                  .__u6_addr32 = {0, 0, 0, 0}
                }
              },
              .sin6_scope_id = 0
            }
          }
        },
        .name = {
          .ptr = 0x0,
          .len = 0
        }
      },
      .left = 1,
      .host_type = KH_IPADDR,
      .host_addr_name = "192.168.1.1",
      .host_addr = {
        .u = {
          .v4 = {
            .sin_family = 2,
            .sin_port = 0,
            .sin_addr = {
              .s_addr = 16885952
            },
            .sin_zero = "\000\000\000\000\000\000\000"
          },
          .v6 = {
            .sin6_family = 2,
            .sin6_port = 0,
            .sin6_flowinfo = 16885952,
            .sin6_addr = {
              .__in6_u = {
                .__u6_addr8 = {'\000',},
                .__u6_addr16 = {0, 0, 0, 0, 0, 0, 0, 0},
                .__u6_addr32 = {0, 0, 0, 0}
              }
            },
            .sin6_scope_id = 0
          }
        }
      },
      .host_nexthop = {
        .u = {
          .v4 = {
            .sin_family = 2,
            .sin_port = 0,
            .sin_addr = {
              .s_addr = 133092740
            },
            .sin_zero = "\000\000\000\000\000\000\000"
          },
          .v6 = {
            .sin6_family = 2,
            .sin6_port = 0,
            .sin6_flowinfo = 133092740,
            .sin6_addr = {
              .__in6_u = {
                .__u6_addr8 = {'\000',},
                .__u6_addr16 = {0, 0, 0, 0, 0, 0, 0, 0},
                .__u6_addr32 = {0, 0, 0, 0}
              }
            },
            .sin6_scope_id = 0
          }
        }
      },
      .host_srcip = {
        .u = {
          .v4 = {
            .sin_family = 0,
            .sin_port = 0,
            .sin_addr = {
              .s_addr = 0
            },
            .sin_zero = "\000\000\000\000\000\000\000"
          },
          .v6 = {
            .sin6_family = 0,
            .sin6_port = 0,
            .sin6_flowinfo = 0,
            .sin6_addr = {
              .__in6_u = {
                .__u6_addr8 = {'\000',},
                .__u6_addr16 = {0, 0, 0, 0, 0, 0, 0, 0},
                .__u6_addr32 = {0, 0, 0, 0}
              }
            },
            .sin6_scope_id = 0
          }
        }
      },
      .client = {
        .addr = {
          .u = {
            .v4 = {
              .sin_family = 2,
              .sin_port = 0,
              .sin_addr = {
                .s_addr = 16885952
              },
              .sin_zero = "\000\000\000\000\000\000\000"
            },
            .v6 = {
              .sin6_family = 2,
              .sin6_port = 0,
              .sin6_flowinfo = 16885952,
              .sin6_addr = {
                .__in6_u = {
                  .__u6_addr8 = {'\000',},
                  .__u6_addr16 = {0, 0, 0, 0, 0, 0, 0, 0},
                  .__u6_addr32 = {0, 0, 0, 0}
                }
              },
              .sin6_scope_id = 0
            }
          }
        },
        .maskbits = 32
      },
      .saved_hint_addr = {
        .u = {
          .v4 = {
            .sin_family = 2,
            .sin_port = 0,
            .sin_addr = {
              .s_addr = 16885952
            },
            .sin_zero = "\000\000\000\000\000\000\000"
          },
          .v6 = {
            .sin6_family = 2,
            .sin6_port = 0,
            .sin6_flowinfo = 16885952,
            .sin6_addr = {
              .__in6_u = {
                .__u6_addr8 = {'\000',},
                .__u6_addr16 = {0, 0, 0, 0, 0, 0, 0, 0},
                .__u6_addr32 = {0, 0, 0, 0}
              }
            },
            .sin6_scope_id = 0
          }
        }
      },
      .host_address_list = {
        .addresses_available = 1,
        .address_list = 0x0,
        .next_address = 0x0
      },
      .key_from_DNS_on_demand = 0,
      .has_client = 0,
      .has_client_wildcard = 0,
      .has_port_wildcard = 0,
      .updown = 0x0,
      .host_port = 500,
      .host_port_specific = 0,
      .port = 0,
      .protocol = 0,
      .sendcert = cert_sendifasked,
      .cert_filename = 0x0,
      .cert = {
        .forced = 0,
        .type = CERT_NONE,
        .u = {
          .x509 = 0x0,
          .pgp = 0x0,
          .blob = {
            .ptr = 0x0,
            .len = 0
          }
        }
      },
      .ca = {
        .ptr = 0x0,
        .len = 0
      },
      .key1 = NULL,
      .key2 = 0x0,
      .groups = 0x0,
      .virt = 0x0,
      .xauth_server = 0,
      .xauth_client = 0,
      .xauth_name = 0x0,
      .xauth_password = 0x0,
      .modecfg_server = 0,
      .modecfg_client = 0
    },
    .that = {
      .id = {
        .has_wildcards = 0,
        .kind = 1,
        .ip_addr = {
          .u = {
            .v4 = {
              .sin_family = 2,
              .sin_port = 0,
              .sin_addr = {
                .s_addr = 133092740
              },
              .sin_zero = "\000\000\000\000\000\000\000"
            },
            .v6 = {
              .sin6_family = 2,
              .sin6_port = 0,
              .sin6_flowinfo = 133092740,
              .sin6_addr = {
                .__in6_u = {
                  .__u6_addr8 = {'\000',},
                  .__u6_addr16 = {0, 0, 0, 0, 0, 0, 0, 0},
                  .__u6_addr32 = {0, 0, 0, 0}
                }
              },
              .sin6_scope_id = 0
            }
          }
        },
        .name = {
          .ptr = 0x0,
          .len = 0
        }
      },
      .left = 0,
      .host_type = KH_IPADDR,
      .host_addr_name = "132.213.238.7",
      .host_addr = {
        .u = {
          .v4 = {
            .sin_family = 2,
            .sin_port = 0,
            .sin_addr = {
              .s_addr = 133092740
            },
            .sin_zero = "\000\000\000\000\000\000\000"
          },
          .v6 = {
            .sin6_family = 2,
            .sin6_port = 0,
            .sin6_flowinfo = 133092740,
            .sin6_addr = {
              .__in6_u = {
                .__u6_addr8 = {'\000',},
                .__u6_addr16 = {0, 0, 0, 0, 0, 0, 0, 0},
                .__u6_addr32 = {0, 0, 0, 0}
              }
            },
            .sin6_scope_id = 0
          }
        }
      },
      .host_nexthop = {
        .u = {
          .v4 = {
            .sin_family = 2,
            .sin_port = 0,
            .sin_addr = {
              .s_addr = 16885952
            },
            .sin_zero = "\000\000\000\000\000\000\000"
          },
          .v6 = {
            .sin6_family = 2,
            .sin6_port = 0,
            .sin6_flowinfo = 16885952,
            .sin6_addr = {
              .__in6_u = {
                .__u6_addr8 = {'\000',},
                .__u6_addr16 = {0, 0, 0, 0, 0, 0, 0, 0},
                .__u6_addr32 = {0, 0, 0, 0}
              }
            },
            .sin6_scope_id = 0
          }
        }
      },
      .host_srcip = {
        .u = {
          .v4 = {
            .sin_family = 0,
            .sin_port = 0,
            .sin_addr = {
              .s_addr = 0
            },
            .sin_zero = "\000\000\000\000\000\000\000"
          },
          .v6 = {
            .sin6_family = 0,
            .sin6_port = 0,
            .sin6_flowinfo = 0,
            .sin6_addr = {
              .__in6_u = {
                .__u6_addr8 = {'\000',},
                .__u6_addr16 = {0, 0, 0, 0, 0, 0, 0, 0},
                .__u6_addr32 = {0, 0, 0, 0}
              }
            },
            .sin6_scope_id = 0
          }
        }
      },
      .client = {
        .addr = {
          .u = {
            .v4 = {
              .sin_family = 2,
              .sin_port = 0,
              .sin_addr = {
                .s_addr = 133092740
              },
              .sin_zero = "\000\000\000\000\000\000\000"
            },
            .v6 = {
              .sin6_family = 2,
              .sin6_port = 0,
              .sin6_flowinfo = 133092740,
              .sin6_addr = {
                .__in6_u = {
                  .__u6_addr8 = {'\000',},
                  .__u6_addr16 = {0, 0, 0, 0, 0, 0, 0, 0},
                  .__u6_addr32 = {0, 0, 0, 0}
                }
              },
              .sin6_scope_id = 0
            }
          }
        },
        .maskbits = 32
      },
      .saved_hint_addr = {
        .u = {
          .v4 = {
            .sin_family = 2,
            .sin_port = 0,
            .sin_addr = {
              .s_addr = 133092740
            },
            .sin_zero = "\000\000\000\000\000\000\000"
          },
          .v6 = {
            .sin6_family = 2,
            .sin6_port = 0,
            .sin6_flowinfo = 133092740,
            .sin6_addr = {
              .__in6_u = {
                .__u6_addr8 = {'\000',},
                .__u6_addr16 = {0, 0, 0, 0, 0, 0, 0, 0},
                .__u6_addr32 = {0, 0, 0, 0}
              }
            },
            .sin6_scope_id = 0
          }
        }
      },
      .host_address_list = {
        .addresses_available = 1,
        .address_list = 0x0,
        .next_address = 0x0
      },
      .key_from_DNS_on_demand = 0,
      .has_client = 0,
      .has_client_wildcard = 0,
      .has_port_wildcard = 0,
      .updown = 0x0,
      .host_port = 500,
      .host_port_specific = 0,
      .port = 0,
      .protocol = 0,
      .sendcert = cert_sendifasked,
      .cert_filename = 0x0,
      .cert = {
        .forced = 0,
        .type = CERT_NONE,
        .u = {
          .x509 = 0x0,
          .pgp = 0x0,
          .blob = {
            .ptr = 0x0,
            .len = 0
          }
        }
      },
      .ca = {
        .ptr = 0x0,
        .len = 0
      },
      .key1 = NULL,
      .key2 = 0x0,
      .groups = 0x0,
      .virt = 0x0,
      .xauth_server = 0,
      .xauth_client = 0,
      .xauth_name = 0x0,
      .xauth_password = 0x0,
      .modecfg_server = 0,
      .modecfg_client = 0
    },
    .eroute_owner = 0,
    .routing = RT_UNROUTED,
    .reqid = 16384
  },
  .instance_serial = 0,
  .prio = 2105345,
  .instance_initiation_ok = 0,
  .kind = CK_PERMANENT,
  .ip_oriented = 1,
  .interface = &parker_if1,
  .initiated = 0,
  .failed_ikev2 = 0,
  .prospective_parent_sa = 1,
  .newest_isakmp_sa = 1,
  .newest_ipsec_sa = 2,
  .extra_debugging = 1049118,
  .end_addr_family = 2,
  .tunnel_addr_family = 0,
  .policy_next = 0x0,
  .gw_info = 0x0,
  .alg_info_esp = 0x0,
  .alg_info_ike = 0x0,
  .IPhost_pair = NULL,
  .IDhost_pair = NULL,
  .IPhp_next = 0x0,
  .IDhp_next = 0x0,
  .ac_next = 0x0,
  .ikev1_requested_ca_names = 0x0,
  .ikev2_requested_ca_hashes = 0x0,
  .modecfg_dns1 = {
    .u = {
      .v4 = {
        .sin_family = 0,
        .sin_port = 0,
        .sin_addr = {
          .s_addr = 0
        },
        .sin_zero = "\000\000\000\000\000\000\000"
      },
      .v6 = {
        .sin6_family = 0,
        .sin6_port = 0,
        .sin6_flowinfo = 0,
        .sin6_addr = {
          .__in6_u = {
            .__u6_addr8 = {'\000',},
            .__u6_addr16 = {0, 0, 0, 0, 0, 0, 0, 0},
            .__u6_addr32 = {0, 0, 0, 0}
          }
        },
        .sin6_scope_id = 0
      }
    }
  },
  .modecfg_dns2 = {
    .u = {
      .v4 = {
        .sin_family = 0,
        .sin_port = 0,
        .sin_addr = {
          .s_addr = 0
        },
        .sin_zero = "\000\000\000\000\000\000\000"
      },
      .v6 = {
        .sin6_family = 0,
        .sin6_port = 0,
        .sin6_flowinfo = 0,
        .sin6_addr = {
          .__in6_u = {
            .__u6_addr8 = {'\000',},
            .__u6_addr16 = {0, 0, 0, 0, 0, 0, 0, 0},
            .__u6_addr32 = {0, 0, 0, 0}
          }
        },
        .sin6_scope_id = 0
      }
    }
  },
  .modecfg_wins1 = {
    .u = {
      .v4 = {
        .sin_family = 0,
        .sin_port = 0,
        .sin_addr = {
          .s_addr = 0
        },
        .sin_zero = "\000\000\000\000\000\000\000"
      },
      .v6 = {
        .sin6_family = 0,
        .sin6_port = 0,
        .sin6_flowinfo = 0,
        .sin6_addr = {
          .__in6_u = {
            .__u6_addr8 = {'\000',},
            .__u6_addr16 = {0, 0, 0, 0, 0, 0, 0, 0},
            .__u6_addr32 = {0, 0, 0, 0}
          }
        },
        .sin6_scope_id = 0
      }
    }
  },
  .modecfg_wins2 = {
    .u = {
      .v4 = {
        .sin_family = 0,
        .sin_port = 0,
        .sin_addr = {
          .s_addr = 0
        },
        .sin_zero = "\000\000\000\000\000\000\000"
      },
      .v6 = {
        .sin6_family = 0,
        .sin6_port = 0,
        .sin6_flowinfo = 0,
        .sin6_addr = {
          .__in6_u = {
            .__u6_addr8 = {'\000',},
            .__u6_addr16 = {0, 0, 0, 0, 0, 0, 0, 0},
            .__u6_addr32 = {0, 0, 0, 0}
          }
        },
        .sin6_scope_id = 0
      }
    }
  },
  .cisco_dns_info = 0x0,
  .cisco_domain_info = 0x0,
  .cisco_banner = 0x0,
  .metric = 0,
  .connmtu = 0
};
void h2h_insert_states(void) {
    /* force h2h_sa_1001 into the statetable */
    h2h_sa_1001.st_hashchain_prev = NULL;
    h2h_sa_1001.st_hashchain_next = NULL;
    insert_state( &h2h_sa_1001 );
    /* force h2h_sa_1002 into the statetable */
    h2h_sa_1002.st_hashchain_prev = NULL;
    h2h_sa_1002.st_hashchain_next = NULL;
    insert_state( &h2h_sa_1002 );
}
