proc hexdump {stuff} {
    binary scan $stuff H* out

    puts "$out"
}

