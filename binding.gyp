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
      "target_name": "wireguard_bridge",
      "sources": [
        "src/addon/wginterface.cpp"
      ],
      "conditions": [
        ["OS=='linux'", {
          "sources": [
            "src/addon/linux/wireguard.c"
          ]
        }],
        ["OS=='win'", {
          "defines": [
            "CallSetupWireguard"
          ],
          "include_dirs": [
            "src/addon/win32/include"
          ],
          "sources": [
            "src/addon/wginterface_win32.cpp",
            "src/addon/key_maneger.c"
          ],
          "libraries": [
            "ws2_32.lib",
            "ntdll.lib",
            "iphlpapi.lib",
            "bcrypt.lib",
            "crypt32.lib",
            "kernel32.lib"
          ]
        }]
      ]
    },
    {
      "target_name": "keygen",
      "sources": [
        "src/addon/key_gen.cpp"
      ],
      "defines": [
        "EXPORT_GEN"
      ]
    }
  ],
}
