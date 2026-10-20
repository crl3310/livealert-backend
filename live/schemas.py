from pydantic import BaseModel, Field
from typing import Literal

# Single source of truth for the scale: used in the schema description AND in both prompts (ai_mode.py).
THREAT_LEVEL_SCALE = (
    "1 = an injury or someone hurt but NOT life-threatening, or any ordinary emergency whose threat poses no risk to life\n"
    "2 = a serious injury that could become life-threatening if not aided right away, "
    "or any emergency that could pose a threat to people if not addressed right away\n"
    "3 = a life-threatening scenario. Someone's life is in immediate danger right now, not merely could become so. "
    "This typically involves one person or a small number of people. Examples: a person who is unconscious, unresponsive "
    "or not breathing; severe uncontrolled bleeding; a gunshot or stab wound; a person trapped in a fire or a crashed vehicle; "
    "drowning or choking; a violent attack on someone, especially with a weapon; an armed threat against specific people.\n"
    "4 = a large-scale life-threatening scenario. Many lives are at risk at once, or the situation is spreading or escalating "
    "so quickly that it will soon endanger many people. Examples: a building or structure fire with people inside or "
    "spreading to others; a multi-vehicle collision with several injured people; an explosion, building collapse or "
    "hazardous-material release; flooding, earthquake or other disaster; an active shooter or mass violence; "
    "a crowd crush or stampede; any scene showing multiple victims or casualties. "
    "Choose 4 over 3 when the number of people at risk is large or growing, not just because a single situation is severe."
)


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
        description="Threat level as an integer from 1 to 4:\n" + THREAT_LEVEL_SCALE,
    )
    summary: str = Field(
        description=(
            "A summary of the incident: what is happening and what is audible. "
            "Describe the events themselves; do not mention the display medium (screen, monitor, TV, recording). "
            "That is reported only in is_screen_recording."
        )
    )

class StrictEmergencyAnalysis(EmergencyAnalysis):
    """Production variant: screen playback / staged footage is rejected. Same fields, stricter descriptions."""
    is_emergency: bool = Field(
        description=(
            "True ONLY if the footage shows a genuine, live, in-person emergency, threat, or hazard. "
            "False for footage of a screen, monitor, TV, movie, pre-recorded or simulated events."
        )
    )
    is_fake: bool = Field(
        description=(
            "True if the content is a joke, prank, staged or simulated scenario, or is footage recorded "
            "off a screen, monitor, TV or other digital playback rather than a genuine live scene."
        )
    )
    summary: str = Field(
        description=(
            "A summary of what is visible and audible in the clip. "
            "If the footage was rejected as screen playback or staged, say so and why."
        )
    )