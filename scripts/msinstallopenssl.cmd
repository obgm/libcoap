IF NOT EXIST "C:\Program Files\OpenSSL\include\openssl\ssl.h" (
  choco install openssl --no-progress
) ELSE (
  echo OpenSSL already installed.
)
