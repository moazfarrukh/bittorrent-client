package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/jackpal/bencode-go"
)

// message meta data message ids
const (
	MsgChoke         uint8 = 0
	MsgUnchoke       uint8 = 1
	MsgInterested    uint8 = 2
	MsgNotInterested uint8 = 3
	MsgHave          uint8 = 4
	MsgBitfield      uint8 = 5
	MsgRequest       uint8 = 6
	MsgPiece         uint8 = 7
	MsgCancel        uint8 = 8
)
const (
	MaxBacklog          = 5
	MaxBlockSize        = 16384
	Port         uint16 = 6881
)

type Handshake struct {
	Pstr     string
	infoHash [20]byte
	PeerID   [20]byte
}
type Bitfield []byte

func (bf Bitfield) HasPiece(index int) bool {
	byteIndex := index / 8
	offset := index % 8
	if byteIndex < 0 || byteIndex >= len(bf) {
		return false
	}
	return bf[byteIndex]>>uint(7-offset)&1 != 0
}
func (bf Bitfield) SetPiece(index int) {
	byteIndex := index / 8
	offset := index % 8

	// silently discard invalid bounded index
	if byteIndex < 0 || byteIndex >= len(bf) {
		return
	}
	bf[byteIndex] |= 1 << uint(7-offset)
}

type Message struct {
	ID      uint8
	payload []byte
}

func (m *Message) serialize() []byte {
	if m == nil {
		return make([]byte, 4)
	}
	// +1 for id
	length := uint32(len(m.payload) + 1)
	buf := make([]byte, 4+length)
	binary.BigEndian.PutUint32(buf[:4], length)
	buf[4] = byte(m.ID)
	copy(buf[5:], m.payload)
	return buf
}

func newHandshake(infohash, peerId [20]byte) *Handshake {
	h := Handshake{
		Pstr:     "BitTorrent protocol",
		infoHash: infohash,
		PeerID:   peerId,
	}
	return &h
}

type bencodeInfo struct {
	Pieces      string `bencode:"pieces"`
	PieceLength int    `bencode:"piece length"`
	Length      int    `bencode:"length"`
	Name        string `bencode:"name"`
}

type Peer struct {
	IP   net.IP
	Port uint16
}

type bencodeTorrent struct {
	Announce string      `bencode:"announce"`
	Info     bencodeInfo `bencode:"info"`
}
type bencodeTracker struct {
	Interval int    `bencode:"interval"`
	Peers    string `bencode:"peers"`
}
type TorrentFile struct {
	Announce    string
	InfoHash    [20]byte
	PieceHashes [][20]byte
	PieceLength int
	Length      int
	Name        string
}

type Torrent struct {
	Peers       []Peer
	Peerid      [20]byte
	infoHash    [20]byte
	PieceHashes [][20]byte
	PieceLength int
	Length      int
	Name        string
}

// piece being worked on
type PieceWork struct {
	index  int
	hash   [20]byte
	length int
}

type pieceResult struct {
	index int
	buf   []byte
}

type pieceProgress struct {
	index      int
	client     *Client
	buf        []byte
	downloaded int
	requested  int
	backlog    int
}

// result of initial tcp handshake
type Client struct {
	Conn     net.Conn
	Choked   bool
	bitField Bitfield
	peer     Peer
	infoHash [20]byte
	peerId   [20]byte
}

func (i *bencodeInfo) get_hash() ([20]byte, error) {
	var buf bytes.Buffer
	err := bencode.Marshal(&buf, *i)
	if err != nil {
		return [20]byte{}, err
	}
	h := sha1.Sum(buf.Bytes())
	return h, err
}
func (i *bencodeInfo) splitHashes() ([][20]byte, error) {
	hashLen := 20
	buf := []byte(i.Pieces)
	if len(buf)%hashLen != 0 {
		err := fmt.Errorf("Recieved incorrect lenght of pieces %d", len(buf))
		return nil, err
	}
	numHashes := len(buf) / hashLen
	hashes := make([][20]byte, numHashes)
	for c := 0; c < numHashes; c++ {
		copy(hashes[c][:], buf[c*hashLen:(c+1)*hashLen])
	}
	return hashes, nil
}

func open(r io.Reader) (*bencodeTorrent, error) {
	bto := bencodeTorrent{}
	err := bencode.Unmarshal(r, &bto)
	if err != nil {
		return nil, err
	}
	return &bto, nil
}
func (bto *bencodeTorrent) toTorrent() (TorrentFile, error) {
	infoHash, err := bto.Info.get_hash()
	if err != nil {
		return TorrentFile{}, err
	}
	hashPieces, err := bto.Info.splitHashes()

	if err != nil {
		return TorrentFile{}, err
	}
	t := TorrentFile{
		Announce:    bto.Announce,
		InfoHash:    infoHash,
		PieceHashes: hashPieces,
		PieceLength: bto.Info.PieceLength,
		Length:      bto.Info.Length,
		Name:        bto.Info.Name}
	return t, nil

}

func (t *TorrentFile) buildTrackerUrl(peerID [20]byte, port uint16) (string, error) {
	base, err := url.Parse(t.Announce)
	if err != nil {
		return "", err
	}
	params := url.Values{
		"info_hash":  []string{string(t.InfoHash[:])},
		"peer_id":    []string{string(peerID[:])},
		"port":       []string{string(strconv.Itoa(int(port)))},
		"uploaded":   []string{"0"},
		"downloaded": []string{"0"},
		"compact":    []string{"1"},
		"left":       []string{strconv.Itoa(t.Length)},
	}
	base.RawQuery = params.Encode()
	return base.String(), nil
}

func Unmarshal_peers(peersbin []byte) ([]Peer, error) {
	const peer_size = 6
	num_peers := (len(peersbin) / peer_size)
	if len(peersbin)%peer_size != 0 {
		err := fmt.Errorf("malformed peers ")
		return []Peer{}, err
	}
	peers := make([]Peer, num_peers)
	for i := 0; i < num_peers; i++ {
		offset := i * peer_size
		peers[i].IP = net.IP(peersbin[offset : offset+4])
		peers[i].Port = binary.BigEndian.Uint16(peersbin[offset+4 : offset+6])
	}

	return peers, nil

}
func (p Peer) String() string {
	return net.JoinHostPort(p.IP.String(), strconv.Itoa(int(p.Port)))
}

func (h *Handshake) Serialize() []byte {
	buf := make([]byte, len(h.Pstr)+49)
	// first bit is the lenght of the pstr
	buf[0] = byte(len(h.Pstr))
	// stores size occupied
	index := 1
	// store pstr
	index += copy(buf[index:], (h.Pstr))
	// empty 8 bytes
	index += copy(buf[index:], make([]byte, 8))
	// infohash
	index += copy(buf[index:], h.infoHash[:])
	// pid
	index += copy(buf[index:], h.PeerID[:])
	return buf
}

func ReadHandshake(r io.Reader) (*Handshake, error) {
	length_buf := make([]byte, 1)
	_, err := io.ReadFull(r, length_buf)
	if err != nil {
		return nil, err
	}
	pstrlen := int(length_buf[0])
	if pstrlen == 0 {
		err = fmt.Errorf("strlen is 0")
		return nil, err
	}
	handShakeBuf := make([]byte, 48+pstrlen)
	_, err = io.ReadFull(r, handShakeBuf)
	if err != nil {
		return nil, err
	}
	var infohash, peer_id [20]byte
	// ignoring first 8 bytes
	copy(infohash[:], handShakeBuf[pstrlen+8:pstrlen+8+20])
	copy(peer_id[:], handShakeBuf[pstrlen+8+20:])
	h := Handshake{
		infoHash: infohash,
		PeerID:   peer_id,
		Pstr:     string(handShakeBuf[0:pstrlen]),
	}

	return &h, nil
}

func (m *Message) Serialize() []byte {
	if m == nil {
		// empty buffer
		// nil keep alive messages
		// will be 0 by defualt
		return make([]byte, 4)
	}
	// +1 is for message id
	length := uint32(len(m.payload) + 1)
	buf := make([]byte, 4+length)
	binary.BigEndian.PutUint32(buf[0:4], length)
	// message id
	buf[4] = byte(m.ID)
	copy(buf[5:], m.payload)
	return buf
}
func ReadMessage(r io.Reader) (*Message, error) {
	lengthBuf := make([]byte, 4)
	// get message length from the stream
	_, err := io.ReadFull(r, lengthBuf)
	if err != nil {
		return nil, err
	}
	// convert bytes to int
	length := binary.BigEndian.Uint32(lengthBuf)
	if length == 0 {
		return nil, nil
	}
	// get message from the stream
	messageBuf := make([]byte, length)
	_, err = io.ReadFull(r, messageBuf)
	if err != nil {
		return nil, err
	}
	m := Message{
		ID:      uint8(messageBuf[0]),
		payload: messageBuf[1:],
	}

	return &m, nil
}

// gets the bitfield from the tcp connection
func recvBitfield(conn net.Conn) (Bitfield, error) {
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	defer conn.SetDeadline(time.Time{}) // finish the deadline
	msg, err := ReadMessage(conn)
	if err != nil {
		return nil, err
	}
	if msg == nil {
		return nil, fmt.Errorf("expected bitfield but got nil")
	}
	if msg.ID != MsgBitfield {
		return nil, fmt.Errorf("expected bitfield but got ID %d", msg.ID)
	}
	return msg.payload, nil
}

// connects to a new peer and trys a handshake to get a connection
func newClient(peer Peer, h Handshake) (*Client, error) {
	conn, err := net.DialTimeout("tcp", peer.String(), 3*time.Second)
	if err != nil {
		return nil, err
	}
	_, err = conn.Write(h.Serialize())

	if err != nil {
		return nil, err
	}
	result, err := ReadHandshake(conn)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(result.infoHash[:], h.infoHash[:]) {
		conn.Close()
		return nil, fmt.Errorf("invalid infohash: expected %x but got %x", h.infoHash, result.infoHash)
	}
	bitf, err := recvBitfield(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}

	return &Client{
		Conn:     conn,
		Choked:   true,
		bitField: bitf,
		peer:     peer,
		infoHash: h.infoHash,
		peerId:   h.PeerID,
	}, nil
}
func (m *Message) parseHave() (int, error) {
	if m.ID != MsgHave {
		return 0, fmt.Errorf("Expected Have %s got %s ID\n", MsgHave, m.ID)
	}
	if len(m.payload) != 4 {

		return 0, fmt.Errorf("Expected payload length of 4 got %d\n", len(m.payload))
	}
	index := int(binary.BigEndian.Uint32(m.payload))
	return index, nil
}

func (c *Client) sendUnchoke() error {
	msg := Message{ID: MsgUnchoke}
	_, err := c.Conn.Write(msg.serialize())
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) sendHave(index int) error {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload[:], uint32(index))
	msg := Message{ID: MsgHave, payload: payload}
	_, err := c.Conn.Write(msg.serialize())
	if err != nil {
		return err
	}
	return nil
}
func (c *Client) sendInterested() error {
	msg := Message{ID: MsgInterested}
	_, err := c.Conn.Write(msg.serialize())
	if err != nil {
		return err
	}
	return nil
}
func formatRequest(index, begin, length int) *Message {
	payload := make([]byte, 12)
	binary.BigEndian.PutUint32(payload[0:4], uint32(index))
	binary.BigEndian.PutUint32(payload[4:8], uint32(begin))
	binary.BigEndian.PutUint32(payload[8:12], uint32(length))
	return &Message{ID: MsgRequest, payload: payload}
}
func (c *Client) sendRequest(index, begin, length int) error {
	msg := formatRequest(index, begin, length)
	_, err := c.Conn.Write(msg.serialize())
	if err != nil {
		return err
	}
	return nil
}
func (c *Client) Read() (*Message, error) {
	msg, err := ReadMessage(c.Conn)
	if err != nil {
		return nil, err
	}
	return msg, nil
}

func ParsePiece(index int, buf []byte, msg *Message) (int, error) {
	if msg.ID != MsgPiece {
		return 0, fmt.Errorf("Expected PIECE (ID %d), got ID %d", MsgPiece, msg.ID)
	}
	if len(msg.payload) < 8 {
		return 0, fmt.Errorf("payload too short. %d < 8", len(msg.payload))
	}
	parsedIndex := int(binary.BigEndian.Uint32(msg.payload[0:4]))
	if parsedIndex != index {
		return 0, fmt.Errorf("Expected index %d, got %d", index, parsedIndex)
	}
	begin := int(binary.BigEndian.Uint32(msg.payload[4:8]))
	if begin >= len(buf) {
		return 0, fmt.Errorf("Begin offset too high. %d >= %d", begin, len(buf))
	}
	data := msg.payload[8:]
	if begin+len(data) > len(buf) {
		return 0, fmt.Errorf("Data too long [%d] for offset %d with length %d", len(data), begin, len(buf))
	}
	copy(buf[begin:], data)
	return len(data), nil
}

func (state *pieceProgress) ReadMessage() error {
	msg, err := state.client.Read()
	if err != nil {
		return err
	}
	if msg == nil {
		return nil
	}
	switch msg.ID {
	case MsgUnchoke:
		state.client.Choked = false
	case MsgChoke:
		state.client.Choked = true
	case MsgHave:
		index, err := msg.parseHave()
		if err != nil {
			return err
		}
		state.client.bitField.SetPiece(index)
	case MsgPiece:
		n, err := ParsePiece(state.index, state.buf, msg)
		if err != nil {
			return err
		}
		state.downloaded += n
		state.backlog--
	}
	return nil
}

func checkIntegrity(work *PieceWork, buf []byte) error {
	hash := sha1.Sum(buf)
	if !bytes.Equal(hash[:], work.hash[:]) {
		return fmt.Errorf("Index %d failed integrity check", work.index)
	}
	return nil
}

func (t *Torrent) calculateBoundsForPiece(index int) (begin int, end int) {
	begin = index * t.PieceLength
	end = begin + t.PieceLength
	if end > t.Length {
		end = t.Length
	}
	return begin, end
}
func (t *Torrent) calculatePieceSize(index int) int {
	begin, end := t.calculateBoundsForPiece(index)
	return end - begin
}
func attemptDownloadPiece(c *Client, pw *PieceWork) ([]byte, error) {
	state := pieceProgress{
		index:  pw.index,
		client: c,
		buf:    make([]byte, pw.length),
	}

	// Setting a deadline helps get unresponsive peers unstuck.
	// 30 seconds is more than enough time to download a 262 KB piece
	c.Conn.SetDeadline(time.Now().Add(30 * time.Second))
	defer c.Conn.SetDeadline(time.Time{}) // Disable the deadline

	for state.downloaded < pw.length {
		// If unchoked, send requests until we have enough unfulfilled requests
		if !state.client.Choked {
			for state.backlog < MaxBacklog && state.requested < pw.length {
				blockSize := MaxBlockSize
				// Last block might be shorter than the typical block
				if pw.length-state.requested < blockSize {
					blockSize = pw.length - state.requested
				}

				err := c.sendRequest(pw.index, state.requested, blockSize)
				if err != nil {
					return nil, err
				}
				state.backlog++
				state.requested += blockSize
			}
		}

		err := state.ReadMessage()
		if err != nil {
			return nil, err
		}
	}

	return state.buf, nil
}

func (t *Torrent) startDownloadWorker(peer Peer, workQueue chan *PieceWork, results chan *pieceResult) {
	h := newHandshake(t.infoHash, t.Peerid)
	c, err := newClient(peer, *h)
	if err != nil {
		log.Printf("Could not handshake with %s. Disconnecting\n", peer.IP)
		return
	}
	defer c.Conn.Close()
	log.Printf("Completed handshake with %s\n", peer.IP)

	c.sendUnchoke()
	c.sendInterested()

	for pw := range workQueue {
		if !c.bitField.HasPiece(pw.index) {
			workQueue <- pw // Put piece back on the queue
			continue
		}

		// Download the piece
		buf, err := attemptDownloadPiece(c, pw)
		if err != nil {
			log.Println("Exiting", err)
			workQueue <- pw // Put piece back on the queue
			return
		}

		err = checkIntegrity(pw, buf)
		if err != nil {
			log.Printf("Piece #%d failed integrity check\n", pw.index)
			workQueue <- pw // Put piece back on the queue
			continue
		}

		c.sendHave(pw.index)
		results <- &pieceResult{pw.index, buf}
	}
}

func (t *Torrent) download() ([]byte, error) {
	log.Println("starting download for ", t.Name)
	WorkQueue := make(chan *PieceWork, len(t.PieceHashes))
	result := make(chan *pieceResult)
	for index, hash := range t.PieceHashes {
		length := t.calculatePieceSize(index)
		WorkQueue <- &PieceWork{index, hash, length}
	}
	//start work
	for _, peer := range t.Peers {
		go t.startDownloadWorker(peer, WorkQueue, result)
	}
	// collecting result into a buffer till its filled
	buf := make([]byte, t.Length)
	donePieces := 0
	for donePieces < len(t.PieceHashes) {
		res := <-result
		begin, end := t.calculateBoundsForPiece(res.index)
		copy(buf[begin:end], res.buf)
		donePieces++
		percent := (float64(donePieces) / float64(len(t.PieceHashes))) * 100
		numWorkers := runtime.NumGoroutine() - 1
		log.Printf("(%0.2f%%) Downloaded piece #%d from %d peers\n", percent, res.index, numWorkers)
	}
	close(WorkQueue)
	return buf, nil

}
func (tor *TorrentFile) requestPeers(peerID [20]byte, port uint16) ([]Peer, error) {
	query, err := tor.buildTrackerUrl(peerID, port)

	if err != nil {

		return nil, fmt.Errorf("error building tracker: ", err)
	}

	resp, err := http.Get(query)
	if err != nil {

		return nil, fmt.Errorf("error getting tracker response: ", err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("error getting response from tracker")
	}
	tracker := bencodeTracker{}
	err = bencode.Unmarshal(resp.Body, &tracker)
	if err != nil {
		return nil, fmt.Errorf("bencode parsing error: ", err)

	}

	available_peers, err := Unmarshal_peers([]byte(tracker.Peers))
	if err != nil {
		fmt.Println()
		return nil, fmt.Errorf("peer error: ", err)
	}
	return available_peers, nil
}
func (t *TorrentFile) DownloadToFile(path string) error {
	var peer_id [20]byte
	_, err := rand.Read(peer_id[:])
	if err != nil {
		return err
	}
	peers, err := t.requestPeers(peer_id, Port)

	torrent := Torrent{
		Peers:       peers,
		Peerid:      peer_id,
		infoHash:    t.InfoHash,
		PieceHashes: t.PieceHashes,
		PieceLength: t.PieceLength,
		Length:      t.Length,
		Name:        t.Name,
	}
	buf, err := torrent.download()
	if err != nil {
		return err
	}
	outfile, err := os.Create(path)
	if err != nil {
		return err
	}
	defer outfile.Close()
	_, err = outfile.Write(buf)
	if err != nil {
		return err
	}
	return nil
}
func main() {
	torrentPath := os.Args[1]
	outputPath := os.Args[2]
	file, err := os.Open(torrentPath)

	if err != nil {
		fmt.Println("Error opening file")
	}

	bt, err := open(file)
	if err != nil {

		fmt.Println("open file error ", err)
	}
	tor, err := bt.toTorrent()
	if err != nil {

		fmt.Println("to torrent error", err)
	}
	err = tor.DownloadToFile(outputPath)
	if err != nil {
		fmt.Println("download err: ", err)
		return
	}

}
