from pydantic import BaseModel, Field
from typing import Literal

class EmergencyAnalysis(BaseModel):
    is_emergency: bool = Field(
        description=(
            "True if the footage depicts a genuine emergency, threat, or hazard "
            "(fire, accident, crime, medical distress, security issue, etc.). "
            "Footage shown on a screen, monitor, or TV still counts as an emergency."
        )
    )
    is_fake: bool = Field(
        description=(
            "True ONLY if the content is a clear joke or prank, or entirely non-emergency or irrelevant. "
            "Do NOT set this to true merely because the video was recorded off a screen."
        )
    )
    is_screen_recording: bool = Field(
        description="True if the camera is recording a phone, tablet, monitor, TV, or laptop screen rather than filming a scene directly. Informational only."
    )
    audio_distress_detected: bool = Field(
        description="True if sounds of distress (screams, gunshots, crash impacts, sirens, explosions) are audible."
    )
    incident_type: Literal["Fire", "Medical", "Crime", "Traffic Accident", "Public Disturbance", "Other"] = Field(
        description="The classified category of the incident."
    )
    threat_level: int = Field(
        ge=1,
        le=4,
        description=(
            "Threat level as an integer from 1 to 4: "
            "1 = low (minor, no immediate danger), "
            "2 = medium (potential danger or injury, needs prompt response), "
            "3 = high (immediate danger to life, urgent response needed), "
            "4 = critical (life-threatening, severe or rapidly escalating, multiple people at risk)."
        ),
    )
    summary: str = Field(
        description="A concise 1-2 sentence summary of what is visible and audible in the clip."
    )