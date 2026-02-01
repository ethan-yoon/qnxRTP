https://larmoire.org/jellyfish/?utm_source=openai



ethan@ethan-B360M-DS3H:~/lab_rtp$ ffmpeg -re -i ~/Downloads/jellyfish-10-mbps-hd-hevc.mkv -an -c:v copy -bsf:v hevc_mp4toannexb -f rtp -sdp_file out.sdp rtp://localhost:5004

>> Re encoding routine..
ethan@ethan-B360M-DS3H:~/lab_rtp$ ffmpeg -re -i ~/Downloads/jellyfish-10-mbps-hd-hevc.mkv   -an -c:v libx265 -x265-params repeat-headers=1:keyint=60   -payload_type 96 -pkt_size 1200   -f rtp -sdp_file out.sdp rtp://127.0.0.1:5004


ethan@ethan-B360M-DS3H:~/lab_rtp/qnxRTP$ g++ -std=c++17 -g src/*.cc src/formats/*.cc -Iinclude -Isrc -pthread -o wlrma


./wlrma nal_dump.bin
python3 nal2hevc.py nal_dump.bin nal_dump.hevc
ffplay -f hevc nal_dump.hevc

