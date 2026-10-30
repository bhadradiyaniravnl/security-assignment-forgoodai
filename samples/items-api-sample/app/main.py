"""Items CRUD API."""
from typing import List

from fastapi import Depends, FastAPI, HTTPException, Query

from app import db
from app.models import Item, ItemIn, ItemUpdate

app = FastAPI(title="Items API")


def get_db_path() -> str:
    return db.DB_PATH


@app.on_event("startup")
def startup() -> None:
    db.init_db(get_db_path())


@app.post("/items", response_model=Item, status_code=201)
def create_item(item: ItemIn, path: str = Depends(get_db_path)) -> Item:
    with db.connect(path) as conn:
        cur = conn.execute(
            "INSERT INTO items (name, description, price, quantity) VALUES (?, ?, ?, ?)",
            (item.name, item.description, item.price, item.quantity),
        )
        return Item(id=cur.lastrowid, **item.model_dump())


@app.get("/items", response_model=List[Item])
def list_items(skip: int = Query(0, ge=0), limit: int = Query(20, ge=1, le=100),
               path: str = Depends(get_db_path)) -> List[Item]:
    with db.connect(path) as conn:
        rows = conn.execute("SELECT * FROM items ORDER BY id LIMIT ? OFFSET ?", (limit, skip)).fetchall()
    return [Item(**dict(r)) for r in rows]


@app.get("/items/{item_id}", response_model=Item)
def get_item(item_id: int, path: str = Depends(get_db_path)) -> Item:
    with db.connect(path) as conn:
        row = conn.execute("SELECT * FROM items WHERE id = ?", (item_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Item not found")
    return Item(**dict(row))


@app.patch("/items/{item_id}", response_model=Item)
def update_item(item_id: int, changes: ItemUpdate, path: str = Depends(get_db_path)) -> Item:
    with db.connect(path) as conn:
        row = conn.execute("SELECT * FROM items WHERE id = ?", (item_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Item not found")
        current = dict(row)
        current.update(changes.model_dump(exclude_unset=True))
        conn.execute(
            "UPDATE items SET name = ?, description = ?, price = ?, quantity = ? WHERE id = ?",
            (current["name"], current["description"], current["price"], current["quantity"], item_id),
        )
    return Item(**current)


@app.delete("/items/{item_id}", status_code=204)
def delete_item(item_id: int, path: str = Depends(get_db_path)) -> None:
    with db.connect(path) as conn:
        conn.execute("DELETE FROM items WHERE id = ?", (item_id,))
