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
        "addons/genKey/key_gen.cpp"
      ]
    },
    {
      "target_name": "wginterface",
      "include_dirs": [
        "addons/tools"
      ],
      "sources": [
        "addons/tools/wginterface.cpp"
      ],
      "conditions": [
        ["OS=='linux'", {
          "sources": [
            "addons/tools/linux/wireguard.c",
            "addons/tools/wginterface-linux.cpp"
          ]
        }],
        ["OS!='linux'", {
          "sources": [
            "addons/tools/wginterface-dummy.cpp"
          ]
        }]
      ]
    }
  ]
}