{
  "targets": [
    {
      "target_name": "wireguard_bridge",
      "cflags": [ "-fpermissive", "-fno-exceptions" ],
      "cflags_cc": [ "-fpermissive", "-fno-exceptions" ],
      "sources": [
        "addon/binding.cc",
        "addon/wgEmbed/wireguard.c",
      ],
      "include_dirs" : [
        "<!(node -p \"require('node-addon-api').include_dir\")",
      ],
      # "libraries": [ "/usr/lib" ]
    }
  ],
}
