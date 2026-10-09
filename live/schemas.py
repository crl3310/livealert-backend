from pydantic import BaseModel, Field
from typing import Literal

class EmergencyAnalysis(BaseModel):
    is_emergency: bool = Field(
        description="True if there is an active, live physical emergency occurring in the real world."
    )
    is_fake: bool = Field(
        description="True if the video is staged, a prank, fake, recorded off a laptop/phone/TV screen, or non-emergency."
    )
    is_screen_recording: bool = Field(
        description="True if the camera is recording a phone, tablet, monitor, TV, or laptop screen showing video footage rather than filming a live scene directly."
    )
    audio_distress_detected: bool = Field(
        description="True if live sounds of distress (screams, gunshots, crash impacts, sirens, explosions) are audible."
    )
    incident_type: Literal["Fire", "Medical", "Crime", "Traffic Accident", "Public Disturbance", "Other"] = Field(
        description="The classified category of the incident."
    )
    threat_level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = Field(
        description="Assessed threat level of the situation."
    )
    summary: str = Field(
        description="A concise 1-2 sentence summary of what is visible and audible in the clip."
    )