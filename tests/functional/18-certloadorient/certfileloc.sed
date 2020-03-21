/loaded .* file/s/'\/.*\/([^/]*)' \(.* bytes\)$/'\1' (X bytes)/
/loading secrets from/s/"\/.*\/([^/]*)"$/"\1"/
/using secrets file/s/\/.*\/([^/]*)$/"\1"/
s/loaded private key for keyid: (.*)/loaded private key for keyid: RANDOM/
/returning non-fips mode/d
/green/s/1:(.*) 2:none/1:KEYID 2:none/
