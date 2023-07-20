{
  "target_defaults": {
    "include_dirs" : [
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
      ],

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
        "src/addon/wginterface.cpp"
      ],
      "conditions": [
        ["OS=='linux'", {
          "sources": [
            "src/addon/linux/wireguard.c"
          ]
        }]
      ]
    }
  ],
}
