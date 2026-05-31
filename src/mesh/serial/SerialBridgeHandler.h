#pragma once
#ifdef HAS_SERIAL_BRIDGE
#include "NodeDB.h"
#include "concurrency/OSThread.h"
#include "mesh/Router.h"

/*
 * Serial bridge between two Meshtastic nodes in the same enclosure.
 *
 * Forwards encrypted MeshPackets bidirectionally over a hardware UART so
 * nodes on different LoRa presets can communicate.  Both nodes must share
 * the same channel PSK; the AES key is derived from the PSK alone, so
 * different channel names (and therefore different hashes) are handled by
 * remapping the hash to the local primary channel on ingress.
 *
 * Wire protocol:
 *   [ 0xAC ][ 0x5B ][ len_hi ][ len_lo ][ MeshPacket protobuf ]
 *
 * Pin configuration (variant.h or platformio.ini build_flags):
 *   SERIAL_BRIDGE_TX    GPIO for TX
 *   SERIAL_BRIDGE_RX    GPIO for RX
 *   SERIAL_BRIDGE_BAUD  baud rate (default 115200)
 *   SERIAL_BRIDGE_PORT  HardwareSerial instance (default Serial1)
 */

#ifndef SERIAL_BRIDGE_BAUD
#define SERIAL_BRIDGE_BAUD 115200
#endif

#ifndef SERIAL_BRIDGE_PORT
#define SERIAL_BRIDGE_PORT Serial1
#endif

// Distinct from the StreamAPI 0x94C3 marker to avoid misparse if a
// phone/CLI is accidentally connected to this port.
#define SERIAL_BRIDGE_START1 0xAC
#define SERIAL_BRIDGE_START2 0x5B
#define SERIAL_BRIDGE_MAX_PACKET   meshtastic_MeshPacket_size
#define SERIAL_BRIDGE_HISTORY_SIZE 64
#define SERIAL_BRIDGE_FRAME_TIMEOUT_MS 2000

class SerialBridgeHandler : private concurrency::OSThread
{
  public:
    SerialBridgeHandler() : OSThread("SerialBridge"), rxPtr(0), historyIdx(0),
                            isRunning(false), stallTs(0), stalledAtIdx(SIZE_MAX)
    {
        memset(history, 0, sizeof(history));
    }

    void start()
    {
        if (isRunning)
            return;
#if defined(SERIAL_BRIDGE_TX) && defined(SERIAL_BRIDGE_RX)
        SERIAL_BRIDGE_PORT.begin(SERIAL_BRIDGE_BAUD, SERIAL_8N1, SERIAL_BRIDGE_RX, SERIAL_BRIDGE_TX);
#else
        SERIAL_BRIDGE_PORT.begin(SERIAL_BRIDGE_BAUD);
#endif
        isRunning = true;
        LOG_INFO("Serial bridge started at %u baud", SERIAL_BRIDGE_BAUD);
    }

    /* Called from Router::send() for every outbound packet. */
    bool onSend(const meshtastic_MeshPacket *mp)
    {
        if (!isRunning || !mp)
            return false;
        if (wasBridged(mp->id))
            return false;

        // Static avoids putting ~480 bytes on an already deep call stack
        // (Router::send → onSend).  Safe because cooperative scheduling
        // ensures onSend and runOnce never interleave.
        static uint8_t buf[SERIAL_BRIDGE_MAX_PACKET];
        size_t len = pb_encode_to_bytes(buf, sizeof(buf), &meshtastic_MeshPacket_msg, mp);
        if (len == 0)
            return false;

        uint8_t header[4] = {
            SERIAL_BRIDGE_START1,
            SERIAL_BRIDGE_START2,
            (uint8_t)((len >> 8) & 0xFF),
            (uint8_t)(len & 0xFF)
        };
        SERIAL_BRIDGE_PORT.write(header, 4);
        SERIAL_BRIDGE_PORT.write(buf, len);
        LOG_DEBUG("Serial bridge: sent id=0x%x len=%u", mp->id, (unsigned)len);
        return true;
    }

  protected:
    virtual int32_t runOnce() override
    {
        if (!isRunning)
            return 500;

        while (SERIAL_BRIDGE_PORT.available()) {
            uint8_t c = (uint8_t)SERIAL_BRIDGE_PORT.read();
            if (rxPtr < sizeof(rxBuf))
                rxBuf[rxPtr++] = c;
            else {
                // Buffer full with no valid frame — discard and resync.
                rxPtr = 0;
                stalledAtIdx = SIZE_MAX;
                rxBuf[rxPtr++] = c;
            }
        }

        tryDecode();
        // Poll faster while bytes are arriving so back-to-back frames are
        // processed without an unnecessary 5 ms gap.
        return SERIAL_BRIDGE_PORT.available() ? 0 : 5;
    }

  private:
    uint8_t  rxBuf[4 + SERIAL_BRIDGE_MAX_PACKET];
    size_t   rxPtr;
    uint32_t history[SERIAL_BRIDGE_HISTORY_SIZE];
    uint8_t  historyIdx; // wraps at SERIAL_BRIDGE_HISTORY_SIZE
    bool     isRunning;
    uint32_t stallTs;
    size_t   stalledAtIdx;

    void markBridged(uint32_t id)
    {
        history[historyIdx] = id;
        historyIdx = (historyIdx + 1) % SERIAL_BRIDGE_HISTORY_SIZE;
    }

    bool wasBridged(uint32_t id) const
    {
        if (id == 0)
            return false;
        for (int i = 0; i < SERIAL_BRIDGE_HISTORY_SIZE; i++)
            if (history[i] == id)
                return true;
        return false;
    }

    void tryDecode()
    {
        // Process all complete frames in the buffer, not just the first one.
        while (true) {
            // Scan for the 2-byte start marker.
            size_t i = 0;
            for (; i + 3 < rxPtr; i++) {
                if (rxBuf[i] == SERIAL_BRIDGE_START1 && rxBuf[i + 1] == SERIAL_BRIDGE_START2)
                    break;
            }
            if (i + 3 >= rxPtr)
                break; // no header found in buffer

            uint16_t len = ((uint16_t)rxBuf[i + 2] << 8) | rxBuf[i + 3];
            if (len == 0 || len > SERIAL_BRIDGE_MAX_PACKET) {
                // Impossible length — header is false positive, skip it.
                consumeBytes(i + 1);
                continue;
            }

            if (rxPtr - i - 4 < len) {
                // Header valid but payload incomplete.  Start or check the
                // stall timer to guard against a false-positive header that
                // would block the buffer forever.
                if (stalledAtIdx != i) {
                    stalledAtIdx = i;
                    stallTs = millis();
                } else if ((millis() - stallTs) > SERIAL_BRIDGE_FRAME_TIMEOUT_MS) {
                    LOG_WARN("Serial bridge: frame timeout, skipping byte %u", (unsigned)i);
                    stalledAtIdx = SIZE_MAX;
                    consumeBytes(i + 1);
                    continue;
                }
                return; // wait for more bytes
            }

            // Full frame — process and loop for any further frames.
            stalledAtIdx = SIZE_MAX;
            ingestPacket(rxBuf + i + 4, len);
            consumeBytes(i + 4 + len);
        }

        // No valid header found.  If the buffer is full, drop the oldest byte
        // to prevent stalling on persistent garbage.
        if (rxPtr >= sizeof(rxBuf))
            consumeBytes(1);
    }

    void consumeBytes(size_t n)
    {
        if (n >= rxPtr) { rxPtr = 0; return; }
        rxPtr -= n;
        memmove(rxBuf, rxBuf + n, rxPtr);
    }

    void ingestPacket(const uint8_t *data, size_t len)
    {
        meshtastic_MeshPacket mp = meshtastic_MeshPacket_init_zero;
        if (!pb_decode_from_bytes(data, len, &meshtastic_MeshPacket_msg, &mp)) {
            LOG_WARN("Serial bridge: failed to decode packet");
            return;
        }
        if (mp.which_payload_variant != meshtastic_MeshPacket_encrypted_tag)
            return;
        if (isFromUs(&mp)) {
            LOG_WARN("Serial bridge: drop spoofed packet from=0x%x", mp.from);
            return;
        }
        if (!router)
            return;

        // Remap the channel hash to the local primary channel so perhapsDecode
        // finds a matching slot and attempts AES decryption.  The AES key is
        // derived from the PSK alone, not the channel name, so this works
        // across meshes with different channel names as long as both share the
        // same PSK.  PKI direct messages carry channel=0 as the Curve25519
        // signal — leave it untouched so the router can attempt PKI decryption.
        if (mp.channel != 0 || isBroadcast(mp.to))
            mp.channel = (uint8_t)channels.getHash(channels.getPrimaryIndex());

        mp.transport_mechanism = meshtastic_MeshPacket_TransportMechanism_TRANSPORT_LORA;
        mp.rx_snr  = 0;
        mp.rx_rssi = 0;

        markBridged(mp.id);
        UniquePacketPoolPacket p = packetPool.allocUniqueCopy(mp);
        router->enqueueReceivedMessage(p.release());
        LOG_DEBUG("Serial bridge: injected id=0x%x from=0x%x", mp.id, mp.from);
    }
};

#endif // HAS_SERIAL_BRIDGE
