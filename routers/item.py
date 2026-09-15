from fastapi import FastAPI,Body
from enum import Enum
from typing import Annotated
from pydantic import BaseModel, Field


class Names(str, Enum):
    kalyan = "kalyan"
    gouthami = "gouthami"
    dinakar = "dinakar"


app = FastAPI()


class Item(BaseModel):
    name: str 
    description: str | None 
    price: float 
    tax: float | None 


@app.get("/items/{item_id}")
async def test(
    item_id: int,
    item: Annotated[
        Item,
        Body(
            openapi_examples={
                "normal": {
                    "summary": "A normal example",
                    "description": "A **normal** item works correctly.",
                    "value": {
                        "name": "Foo",
                        "description": "A very nice Item",
                        "price": 35.4,
                        "tax": 3.2,
                    },
                },
                "converted": {
                    "summary": "An example with converted data",
                    "description": "FastAPI can convert price `strings` to actual `numbers` automatically",
                    "value": {
                        "name": "Bar",
                        "price": "35.4",
                    },
                },
                "invalid": {
                    "summary": "Invalid data is rejected with an error",
                    "value": {
                        "name": "Baz",
                        "price": "thirty five point four",
                    },
                },
            },
        ),

    ],
):
    return f"Item ID: {item_id}"
