# MTProxy (Telegram Official Proxy) Docker Image
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install MTProxy (official Telegram repository)
RUN curl -fsSL https://github.com/TelegramMessenger/MTProxy/releases/download/latest/mtproxy-linux-x64.tar.gz -o mtproxy.tar.gz \
    && tar -xzf mtproxy.tar.gz -C /usr/local/bin/ \
    && rm mtproxy.tar.gz \
    && chmod +x /usr/local/bin/mtproxy

# Create config directory
RUN mkdir -p /config

EXPOSE 443 9090 9091

CMD ["mtproxy", "--config", "/config/config.toml"]
