{
  "targets": [
    {
      "target_name": "wireguard_bridge",
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
      "sources": [
        "src/addon/binding.cpp"
      ],
      "include_dirs" : [
        "<!(node -p \"require('node-addon-api').include_dir\")"
      ],
      "defines": [
        "NAPI_DISABLE_CPP_EXCEPTIONS"
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
