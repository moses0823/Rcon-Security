package tw.rconsecurity.protocol;

public record Packet(byte type, byte[] payload) {
}
