package webrtc

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"

	"github.com/pion/webrtc/v3"
)

type WebRTCManager struct {
	api           *webrtc.API
	peerConnections map[string]*webrtc.PeerConnection
	connMux       sync.RWMutex
	
	// Callbacks
	onICECandidate    func(userID string, candidate *webrtc.ICECandidate)
	onTrack          func(userID string, track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver)
	onDataChannel    func(userID string, channel *webrtc.DataChannel)
}

type SignalingMessage struct {
	Type      string      `json:"type"`
	UserID    string      `json:"user_id"`
	ChannelID string      `json:"channel_id"`
	Data      interface{} `json:"data"`
}

func NewWebRTCManager() *WebRTCManager {
	// Create a MediaEngine object to configure the supported codec
	m := &webrtc.MediaEngine{}
	
	// Setup the codecs you want to use
	if err := m.RegisterCodec(webrtc.RTPCodecParameters{
		RTPCodecCapability: webrtc.RTPCodecCapability{
			MimeType:     webrtc.MimeTypeOpus,
			ClockRate:    48000,
			Channels:     2,
			SDPFmtpLine:  "minptime=10;useinbandfec=1",
		},
		PayloadType: 111,
	}, webrtc.RTPCodecTypeAudio); err != nil {
		log.Printf("Failed to register Opus codec: %v", err)
	}

	if err := m.RegisterCodec(webrtc.RTPCodecParameters{
		RTPCodecCapability: webrtc.RTPCodecCapability{
			MimeType:    webrtc.MimeTypeVP8,
			ClockRate:   90000,
			RTCPFeedback: []webrtc.RTCPFeedback{
				{Type: "goog-remb", Parameter: ""},
				{Type: "ccm", Parameter: "fir"},
				{Type: "nack", Parameter: ""},
				{Type: "nack", Parameter: "pli"},
			},
		},
		PayloadType: 96,
	}, webrtc.RTPCodecTypeVideo); err != nil {
		log.Printf("Failed to register VP8 codec: %v", err)
	}

	// Create the API object with the MediaEngine
	api := webrtc.NewAPI(webrtc.WithMediaEngine(m))

	return &WebRTCManager{
		api:             api,
		peerConnections: make(map[string]*webrtc.PeerConnection),
	}
}

func (w *WebRTCManager) SetCallbacks(
	onICECandidate func(userID string, candidate *webrtc.ICECandidate),
	onTrack func(userID string, track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver),
	onDataChannel func(userID string, channel *webrtc.DataChannel),
) {
	w.onICECandidate = onICECandidate
	w.onTrack = onTrack
	w.onDataChannel = onDataChannel
}

func (w *WebRTCManager) CreatePeerConnection(userID string) error {
	// STUN servers for NAT traversal
	config := webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{
			{
				URLs: []string{"stun:stun.l.google.com:19302"},
			},
		},
	}

	peerConnection, err := w.api.NewPeerConnection(config)
	if err != nil {
		return fmt.Errorf("failed to create peer connection: %v", err)
	}

	// Set up ICE candidate handler
	peerConnection.OnICECandidate(func(candidate *webrtc.ICECandidate) {
		if candidate != nil && w.onICECandidate != nil {
			w.onICECandidate(userID, candidate)
		}
	})

	// Set up track handler for receiving media
	peerConnection.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
		log.Printf("Received track from %s: %s", userID, track.Kind())
		if w.onTrack != nil {
			w.onTrack(userID, track, receiver)
		}
	})

	// Set up data channel handler
	peerConnection.OnDataChannel(func(channel *webrtc.DataChannel) {
		log.Printf("Received data channel from %s: %s", userID, channel.Label())
		if w.onDataChannel != nil {
			w.onDataChannel(userID, channel)
		}
	})

	// Connection state change handler
	peerConnection.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		log.Printf("Peer connection state changed for %s: %s", userID, state.String())
		
		if state == webrtc.PeerConnectionStateFailed || 
		   state == webrtc.PeerConnectionStateClosed ||
		   state == webrtc.PeerConnectionStateDisconnected {
			w.RemovePeerConnection(userID)
		}
	})

	w.connMux.Lock()
	w.peerConnections[userID] = peerConnection
	w.connMux.Unlock()

	return nil
}

func (w *WebRTCManager) CreateOffer(userID string) (*webrtc.SessionDescription, error) {
	w.connMux.RLock()
	peerConnection, exists := w.peerConnections[userID]
	w.connMux.RUnlock()

	if !exists {
		return nil, fmt.Errorf("no peer connection for user %s", userID)
	}

	offer, err := peerConnection.CreateOffer(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create offer: %v", err)
	}

	if err := peerConnection.SetLocalDescription(offer); err != nil {
		return nil, fmt.Errorf("failed to set local description: %v", err)
	}

	return &offer, nil
}

func (w *WebRTCManager) CreateAnswer(userID string, offer webrtc.SessionDescription) (*webrtc.SessionDescription, error) {
	w.connMux.RLock()
	peerConnection, exists := w.peerConnections[userID]
	w.connMux.RUnlock()

	if !exists {
		return nil, fmt.Errorf("no peer connection for user %s", userID)
	}

	if err := peerConnection.SetRemoteDescription(offer); err != nil {
		return nil, fmt.Errorf("failed to set remote description: %v", err)
	}

	answer, err := peerConnection.CreateAnswer(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create answer: %v", err)
	}

	if err := peerConnection.SetLocalDescription(answer); err != nil {
		return nil, fmt.Errorf("failed to set local description: %v", err)
	}

	return &answer, nil
}

func (w *WebRTCManager) SetRemoteDescription(userID string, desc webrtc.SessionDescription) error {
	w.connMux.RLock()
	peerConnection, exists := w.peerConnections[userID]
	w.connMux.RUnlock()

	if !exists {
		return fmt.Errorf("no peer connection for user %s", userID)
	}

	return peerConnection.SetRemoteDescription(desc)
}

func (w *WebRTCManager) AddICECandidate(userID string, candidate webrtc.ICECandidateInit) error {
	w.connMux.RLock()
	peerConnection, exists := w.peerConnections[userID]
	w.connMux.RUnlock()

	if !exists {
		return fmt.Errorf("no peer connection for user %s", userID)
	}

	return peerConnection.AddICECandidate(candidate)
}

func (w *WebRTCManager) AddTrack(userID string, track webrtc.TrackLocal) (*webrtc.RTPSender, error) {
	w.connMux.RLock()
	peerConnection, exists := w.peerConnections[userID]
	w.connMux.RUnlock()

	if !exists {
		return nil, fmt.Errorf("no peer connection for user %s", userID)
	}

	sender, err := peerConnection.AddTrack(track)
	if err != nil {
		return nil, fmt.Errorf("failed to add track: %v", err)
	}

	return sender, nil
}

func (w *WebRTCManager) CreateDataChannel(userID, label string) (*webrtc.DataChannel, error) {
	w.connMux.RLock()
	peerConnection, exists := w.peerConnections[userID]
	w.connMux.RUnlock()

	if !exists {
		return nil, fmt.Errorf("no peer connection for user %s", userID)
	}

	dataChannel, err := peerConnection.CreateDataChannel(label, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create data channel: %v", err)
	}

	return dataChannel, nil
}

func (w *WebRTCManager) RemovePeerConnection(userID string) {
	w.connMux.Lock()
	defer w.connMux.Unlock()

	if peerConnection, exists := w.peerConnections[userID]; exists {
		peerConnection.Close()
		delete(w.peerConnections, userID)
		log.Printf("Removed peer connection for user %s", userID)
	}
}

func (w *WebRTCManager) GetPeerConnection(userID string) (*webrtc.PeerConnection, bool) {
	w.connMux.RLock()
	defer w.connMux.RUnlock()
	
	peerConnection, exists := w.peerConnections[userID]
	return peerConnection, exists
}

func (w *WebRTCManager) GetConnectedPeers() []string {
	w.connMux.RLock()
	defer w.connMux.RUnlock()

	peers := make([]string, 0, len(w.peerConnections))
	for userID, peerConnection := range w.peerConnections {
		if peerConnection.ConnectionState() == webrtc.PeerConnectionStateConnected {
			peers = append(peers, userID)
		}
	}
	return peers
}

func (w *WebRTCManager) Close() {
	w.connMux.Lock()
	defer w.connMux.Unlock()

	for userID, peerConnection := range w.peerConnections {
		peerConnection.Close()
		log.Printf("Closed peer connection for user %s", userID)
	}
	w.peerConnections = make(map[string]*webrtc.PeerConnection)
}

// Helper function to create a local audio track
func CreateAudioTrack() (webrtc.TrackLocal, error) {
	track, err := webrtc.NewTrackLocalStaticSample(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus},
		"audio",
		"pion-audio",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create audio track: %v", err)
	}
	return track, nil
}

// Helper function to create a local video track
func CreateVideoTrack() (webrtc.TrackLocal, error) {
	track, err := webrtc.NewTrackLocalStaticSample(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP8},
		"video",
		"pion-video",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create video track: %v", err)
	}
	return track, nil
}

