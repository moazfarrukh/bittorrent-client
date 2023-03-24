# Gorrent
A basic bittorent client written in go

This is a learning project inspired from https://blog.jse.li/posts/torrent/
## Instructions
1. Download your torrent file
2. Run main.go with the following arguments
```
go run main.go [torrent file name] [output file name]
```
## Limitations
- Does not work on multifile torrents
- Only supports torrent files (no magnet links)
- Does not support seeding
- Works only for http trackers
