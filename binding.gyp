{
  "target_defaults": {
    "include_dirs": [
      "<!(node -p \"require('node-addon-api').include_dir\")"
    ],
    "defines": [
      "NAPI_DISABLE_CPP_EXCEPTIONS"
    ],
    "cflags": [
      "-fpermissive",
      "-fno-exceptions",
      "-w",
      "-fpermissive",
      "-fPIC",
      "-static"
    ],
    "cflags_cc": [
      "-fpermissive",
      "-fno-exceptions",
      "-w",
      "-fpermissive",
      "-fPIC",
      "-static"
    ]
  },
  "targets": [
    {
      "target_name": "keygen",
      "sources": [
        "src/addon/key_gen.cpp"
      ]
    },
    {
      "target_name": "wireguard_bridge",
      "sources": [
        "src/addon/wg/src/curve25519.c",
        "src/addon/wg/src/config.c",
        "src/addon/wg/src/ipc.c",
        "src/addon/wg/src/encoding.c",
        "src/addon/wg_interface.cpp"
      ],
      "conditions": [
        [
          "OS=='win'",
          {
            "cflags": [
              "-idirafter",
              "uapi/windows",
              "-include",
              "wincompat/compat.h",
              "-DWINVER=0x0601",
              "-D_WIN32_WINNT=0x0601",
              "-flto"
            ],
            "include_dirs": [
              "src/addon/wg/src/wincompat/include"
            ],
            "sources": [
                "src/addon/wg/src/wincompat/loader.c",
                "src/addon/wg/src/wincompat/init.c",
                "src/addon/wg/src/wincompat/libc.c"
            ]
          }
        ],
        [
          "OS=='linux'",
          {
            "cflags": [
              "-idirafter",
              "src/addon/wg/src/uapi/linux"
            ]
          }
        ],
        [
          "OS!='win'",
          {
            "defines": [
              "RUNSTATEDIR=\"/var/run\""
            ],
            "cflags": [
              "-O3",
              "-Wall",
              "-Wextra",
              "-MMD",
              "-MP"
            ]
          }
        ]
      ]
    }
  ]
}