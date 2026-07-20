from pydantic import BaseModel, Field
from typing import Optional

class HazardReport(BaseModel):
    title: str = Field(..., description="Short descriptive title of the hazard")
    category: str = Field(..., description="Category filter (e.g., Infrastructure, Traffic, Fire, Utility, Environmental)")
    description: Optional[str] = Field(None, description="Detailed description of the hazard observed")
    image_url: Optional[str] = Field(None, description="Optional public URL of the uploaded hazard image")

class HazardImageAnalysis(BaseModel):
    detected_issue: str = Field(
        description="Concise description of the physical issue observed in the image."
    )
    summary: str = Field(
        description="1-sentence summary of the condition reported for community review."
    )