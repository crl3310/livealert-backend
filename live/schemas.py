from pydantic import BaseModel, Field
from typing import Literal

class EmergencyAnalysis(BaseModel):
    incident_type: str = Field(
        description="The classified category of the incident (e.g., Physical Assault, Car Accident, Fire Emergency, Medical Crisis, Suspicious Activity, Verbal Fight, Active Shooter, Unknown)."
    )
    threat_level: Literal["LOW", "MEDIUM", "HIGH"] = Field(
        description="The priority classification. HIGH: Immediate threat to life, active violence, weapon drawn, fire, unconsciousness. MEDIUM: Escalating danger, non-life-threatening accidents, verbal fights. LOW: Non-violent, minor property damage, or false alarms."
    )
    summary: str = Field(
        description="A concise, objective 1-sentence summary of the visual and audio evidence observed in the clip."
    )
    reasoning: str = Field(
        description="A detailed 2-3 sentence technical justification of why this threat level and incident type were determined based on specific visual frames or sounds heard."
    )