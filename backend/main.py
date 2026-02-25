import contextlib
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.router import router as api_router
from services.scheduler import start_scheduler, shutdown_scheduler
import threading
from services.email_watcher import start_email_watcher

@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Setup background tasks
    start_scheduler()
    
    # Start the continuous IMAP IDLE watcher in a daemon thread
    watcher_thread = threading.Thread(target=start_email_watcher, daemon=True, name="IMAP_IDLE_Watcher")
    watcher_thread.start()
    
    yield
    # Shutdown: Cleanly stop background tasks
    shutdown_scheduler()

app = FastAPI(title="AI Phishing Checker API", lifespan=lifespan)

# Configure CORS for frontend access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, set to specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix="/api")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
