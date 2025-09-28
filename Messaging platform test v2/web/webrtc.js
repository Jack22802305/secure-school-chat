class WebRTCClient {
    constructor(userId, socket) {
        this.userId = userId;
        this.socket = socket;
        this.peerConnections = new Map();
        this.localStream = null;
        this.remoteStreams = new Map();
        this.dataChannels = new Map();
        
        // WebRTC configuration
        this.config = {
            iceServers: [
                { urls: 'stun:stun.l.google.com:19302' },
                { urls: 'stun:stun1.l.google.com:19302' }
            ]
        };
        
        // Callbacks
        this.onRemoteStream = null;
        this.onRemoteStreamRemoved = null;
        this.onDataChannelMessage = null;
        
        this.setupSocketHandlers();
    }
    
    setupSocketHandlers() {
        this.socket.on('webrtc_offer', async (data) => {
            await this.handleOffer(data);
        });
        
        this.socket.on('webrtc_answer', async (data) => {
            await this.handleAnswer(data);
        });
        
        this.socket.on('webrtc_ice_candidate', async (data) => {
            await this.handleICECandidate(data);
        });
        
        this.socket.on('user_left_voice', (data) => {
            this.removePeerConnection(data.user_id);
        });
    }
    
    async startVoiceCall(channelId) {
        try {
            this.localStream = await navigator.mediaDevices.getUserMedia({
                audio: {
                    echoCancellation: true,
                    noiseSuppression: true,
                    autoGainControl: true
                },
                video: false
            });
            
            // Notify server that we joined voice channel
            this.socket.emit('join_voice_channel', {
                channel_id: channelId,
                user_id: this.userId
            });
            
            return this.localStream;
        } catch (error) {
            console.error('Failed to start voice call:', error);
            throw error;
        }
    }
    
    async startVideoCall(channelId) {
        try {
            this.localStream = await navigator.mediaDevices.getUserMedia({
                audio: {
                    echoCancellation: true,
                    noiseSuppression: true,
                    autoGainControl: true
                },
                video: {
                    width: { ideal: 1280 },
                    height: { ideal: 720 },
                    frameRate: { ideal: 30 }
                }
            });
            
            // Notify server that we joined voice channel with video
            this.socket.emit('join_voice_channel', {
                channel_id: channelId,
                user_id: this.userId,
                video: true
            });
            
            return this.localStream;
        } catch (error) {
            console.error('Failed to start video call:', error);
            throw error;
        }
    }
    
    async createPeerConnection(peerId) {
        const peerConnection = new RTCPeerConnection(this.config);
        
        // Add local stream tracks
        if (this.localStream) {
            this.localStream.getTracks().forEach(track => {
                peerConnection.addTrack(track, this.localStream);
            });
        }
        
        // Handle remote stream
        peerConnection.ontrack = (event) => {
            console.log('Received remote track from', peerId);
            const [remoteStream] = event.streams;
            this.remoteStreams.set(peerId, remoteStream);
            
            if (this.onRemoteStream) {
                this.onRemoteStream(peerId, remoteStream);
            }
        };
        
        // Handle ICE candidates
        peerConnection.onicecandidate = (event) => {
            if (event.candidate) {
                this.socket.emit('webrtc_ice_candidate', {
                    to: peerId,
                    candidate: event.candidate
                });
            }
        };
        
        // Handle connection state changes
        peerConnection.onconnectionstatechange = () => {
            console.log(`Peer connection state with ${peerId}:`, peerConnection.connectionState);
            
            if (peerConnection.connectionState === 'disconnected' || 
                peerConnection.connectionState === 'failed' ||
                peerConnection.connectionState === 'closed') {
                this.removePeerConnection(peerId);
            }
        };
        
        // Create data channel for text chat during calls
        const dataChannel = peerConnection.createDataChannel('chat', {
            ordered: true
        });
        
        dataChannel.onopen = () => {
            console.log('Data channel opened with', peerId);
        };
        
        dataChannel.onmessage = (event) => {
            if (this.onDataChannelMessage) {
                this.onDataChannelMessage(peerId, event.data);
            }
        };
        
        this.dataChannels.set(peerId, dataChannel);
        
        // Handle incoming data channels
        peerConnection.ondatachannel = (event) => {
            const channel = event.channel;
            channel.onmessage = (event) => {
                if (this.onDataChannelMessage) {
                    this.onDataChannelMessage(peerId, event.data);
                }
            };
        };
        
        this.peerConnections.set(peerId, peerConnection);
        return peerConnection;
    }
    
    async createOffer(peerId) {
        const peerConnection = await this.createPeerConnection(peerId);
        
        try {
            const offer = await peerConnection.createOffer({
                offerToReceiveAudio: true,
                offerToReceiveVideo: true
            });
            
            await peerConnection.setLocalDescription(offer);
            
            this.socket.emit('webrtc_offer', {
                to: peerId,
                offer: offer
            });
            
        } catch (error) {
            console.error('Failed to create offer:', error);
            throw error;
        }
    }
    
    async handleOffer(data) {
        const { from, offer } = data;
        
        try {
            const peerConnection = await this.createPeerConnection(from);
            await peerConnection.setRemoteDescription(offer);
            
            const answer = await peerConnection.createAnswer();
            await peerConnection.setLocalDescription(answer);
            
            this.socket.emit('webrtc_answer', {
                to: from,
                answer: answer
            });
            
        } catch (error) {
            console.error('Failed to handle offer:', error);
        }
    }
    
    async handleAnswer(data) {
        const { from, answer } = data;
        const peerConnection = this.peerConnections.get(from);
        
        if (peerConnection) {
            try {
                await peerConnection.setRemoteDescription(answer);
            } catch (error) {
                console.error('Failed to handle answer:', error);
            }
        }
    }
    
    async handleICECandidate(data) {
        const { from, candidate } = data;
        const peerConnection = this.peerConnections.get(from);
        
        if (peerConnection) {
            try {
                await peerConnection.addIceCandidate(candidate);
            } catch (error) {
                console.error('Failed to add ICE candidate:', error);
            }
        }
    }
    
    sendDataChannelMessage(peerId, message) {
        const dataChannel = this.dataChannels.get(peerId);
        if (dataChannel && dataChannel.readyState === 'open') {
            dataChannel.send(message);
        }
    }
    
    broadcastDataChannelMessage(message) {
        this.dataChannels.forEach((dataChannel, peerId) => {
            if (dataChannel.readyState === 'open') {
                dataChannel.send(message);
            }
        });
    }
    
    removePeerConnection(peerId) {
        const peerConnection = this.peerConnections.get(peerId);
        if (peerConnection) {
            peerConnection.close();
            this.peerConnections.delete(peerId);
        }
        
        const dataChannel = this.dataChannels.get(peerId);
        if (dataChannel) {
            dataChannel.close();
            this.dataChannels.delete(peerId);
        }
        
        const remoteStream = this.remoteStreams.get(peerId);
        if (remoteStream) {
            this.remoteStreams.delete(peerId);
            if (this.onRemoteStreamRemoved) {
                this.onRemoteStreamRemoved(peerId);
            }
        }
    }
    
    async toggleMute() {
        if (this.localStream) {
            const audioTrack = this.localStream.getAudioTracks()[0];
            if (audioTrack) {
                audioTrack.enabled = !audioTrack.enabled;
                return !audioTrack.enabled; // Return true if muted
            }
        }
        return false;
    }
    
    async toggleVideo() {
        if (this.localStream) {
            const videoTrack = this.localStream.getVideoTracks()[0];
            if (videoTrack) {
                videoTrack.enabled = !videoTrack.enabled;
                return !videoTrack.enabled; // Return true if video disabled
            }
        }
        return false;
    }
    
    async shareScreen() {
        try {
            const screenStream = await navigator.mediaDevices.getDisplayMedia({
                video: true,
                audio: true
            });
            
            // Replace video track in all peer connections
            const videoTrack = screenStream.getVideoTracks()[0];
            
            this.peerConnections.forEach(async (peerConnection) => {
                const sender = peerConnection.getSenders().find(s => 
                    s.track && s.track.kind === 'video'
                );
                
                if (sender) {
                    await sender.replaceTrack(videoTrack);
                }
            });
            
            // Handle screen share ending
            videoTrack.onended = () => {
                this.stopScreenShare();
            };
            
            return screenStream;
        } catch (error) {
            console.error('Failed to share screen:', error);
            throw error;
        }
    }
    
    async stopScreenShare() {
        if (this.localStream) {
            const videoTrack = this.localStream.getVideoTracks()[0];
            
            if (videoTrack) {
                // Replace screen share track with camera track
                this.peerConnections.forEach(async (peerConnection) => {
                    const sender = peerConnection.getSenders().find(s => 
                        s.track && s.track.kind === 'video'
                    );
                    
                    if (sender) {
                        await sender.replaceTrack(videoTrack);
                    }
                });
            }
        }
    }
    
    leaveCall() {
        // Stop local stream
        if (this.localStream) {
            this.localStream.getTracks().forEach(track => {
                track.stop();
            });
            this.localStream = null;
        }
        
        // Close all peer connections
        this.peerConnections.forEach((peerConnection, peerId) => {
            this.removePeerConnection(peerId);
        });
        
        // Notify server
        this.socket.emit('leave_voice_channel', {
            user_id: this.userId
        });
    }
    
    getConnectionStats(peerId) {
        const peerConnection = this.peerConnections.get(peerId);
        if (peerConnection) {
            return peerConnection.getStats();
        }
        return null;
    }
    
    setCallbacks(callbacks) {
        this.onRemoteStream = callbacks.onRemoteStream;
        this.onRemoteStreamRemoved = callbacks.onRemoteStreamRemoved;
        this.onDataChannelMessage = callbacks.onDataChannelMessage;
    }
}

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = WebRTCClient;
} else {
    window.WebRTCClient = WebRTCClient;
}

