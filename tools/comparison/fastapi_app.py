"""Comparison workloads; run with one uvicorn worker, as a separately labeled stack.

This fixture compares success-path constraints, not complete framework semantics.
"""
from typing import Annotated
from fastapi import FastAPI, Query
from pydantic import BaseModel, Field

app = FastAPI()

class Item(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    count: int = Field(ge=1, le=100)

@app.get("/json", response_model=Item)
async def get_json():
    return Item(name="widget", count=3)

@app.post("/validated", response_model=Item)
async def validated(item: Item):
    return item

@app.get("/query", response_model=Item)
async def query(count: Annotated[int, Query(ge=1, le=100)]):
    return Item(name="widget", count=count)
