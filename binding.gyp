{
  "target_defaults": {
    "cflags!": [ "-fno-exceptions" ],
    "cflags_cc!": [ "-fno-exceptions" ],
    "defines": [
      "NAPI_DISABLE_CPP_EXCEPTIONS"
    ],
    "conditions": [
      ["OS=='win'", {
        "defines": [
          "_HAS_EXCEPTIONS=1"
        ],
        "msvs_settings": {
          "VCCLCompilerTool": {
            "ExceptionHandling": 1
          },
        },
      }],
      ["OS=='mac'", {
        "xcode_settings": {
          "GCC_ENABLE_CPP_EXCEPTIONS": "YES"
        },
      }],
    ],
    "include_dirs": [
      "<!(node -p \"require('node-addon-api').include_dir\")"
    ],
    "cflags": [
      "-fpermissive",
      "-fexceptions",
      "-w",
      "-fpermissive",
      "-fPIC",
      "-static"
    ],
    "cflags_cc": [
      "-fpermissive",
      "-fexceptions",
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
          "defines": [
            "LISTDEV",
            "GETCONFIG",
            "SETCONFIG",
            "DELIFACE"
          ],
          "sources": [
            "addons/tools/linux/wireguard.c",
            "addons/tools/wginterface-linux.cpp"
          ]
        }],
        ["OS=='mac'", {
          "cflags!": [ "-fno-exceptions" ],
          "cflags_cc!": [ "-fno-exceptions" ],
          "cflags_cc": [ "-fexceptions" ],
          "cflags": [ "-fexceptions" ],
          "xcode_settings": {
            "GCC_ENABLE_CPP_EXCEPTIONS": "YES"
          },
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