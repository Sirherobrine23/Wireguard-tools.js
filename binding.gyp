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
        "src/addon/binding.cpp",
        "src/addon/wgEmbed/wireguard.c",
      ],
      "include_dirs" : [
        "<!(node -p \"require('node-addon-api').include_dir\")"
      ],
    }
  ],
}
