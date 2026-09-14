package tw.rconsecurity.config;

public record LoggingSettings(boolean successfulAuth, boolean failedAuth, boolean commands) {
}
