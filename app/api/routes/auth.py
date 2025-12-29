"""Authentication API endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from app.api.dependencies import get_auth_service, require_auth
from app.models.auth import (
    ChangePasswordRequest,
    LoginRequest,
    LoginResponse,
    Session,
    SessionInfo,
)
from app.services.auth_service import AuthService

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


@router.post("/login", response_model=LoginResponse)
def login(
    request: Request,
    login_request: LoginRequest,
    auth_service: AuthService = Depends(get_auth_service),
):
    """
    Authenticate with password and receive session token.

    For API clients: Use the returned token as Bearer token in Authorization header.
    """
    if not auth_service.is_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authentication is disabled",
        )

    if not auth_service.verify_password(login_request.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid password",
        )

    # Create session with client info
    session = auth_service.create_session(
        user_agent=request.headers.get("User-Agent"),
        ip_address=request.client.host if request.client else None,
    )

    return LoginResponse(
        token=session.token,
        expires_at=session.expires_at,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    response: Response,
    session: Session = Depends(require_auth),
    auth_service: AuthService = Depends(get_auth_service),
):
    """Invalidate current session token."""
    auth_service.invalidate_session(session.token)

    # Clear cookies for web clients
    response.delete_cookie("session_token")
    response.delete_cookie("csrf_token")


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(
    request: ChangePasswordRequest,
    session: Session = Depends(require_auth),
    auth_service: AuthService = Depends(get_auth_service),
):
    """
    Change the password. Requires current password.
    All existing sessions will be invalidated.
    """
    if not auth_service.change_password(
        request.current_password,
        request.new_password,
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )


@router.get("/session", response_model=SessionInfo)
def get_session_info(session: Session = Depends(require_auth)):
    """Get information about the current session."""
    return SessionInfo(
        created_at=session.created_at,
        expires_at=session.expires_at,
        is_valid=True,
    )
