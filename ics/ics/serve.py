"""python -m ics.serve : run uvicorn on 127.0.0.1 with proxy header trust disabled (L1: X-Forwarded-For is not honoured)."""
import uvicorn


def make_config(host: str = "127.0.0.1", port: int = 8088) -> uvicorn.Config:
    return uvicorn.Config("ics.main:create_app", factory=True, host=host, port=port,
                          proxy_headers=False, forwarded_allow_ips="", server_header=False, date_header=True)


if __name__ == "__main__":
    uvicorn.Server(make_config()).run()
