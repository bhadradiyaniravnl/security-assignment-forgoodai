# items-api-sample

A small FastAPI + SQLite CRUD service for inventory items.

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

| Method | Path | Description |
|---|---|---|
| POST | /items | Create an item |
| GET | /items?skip=&limit= | List items |
| GET | /items/{id} | Get one item |
| PATCH | /items/{id} | Partially update an item |
| DELETE | /items/{id} | Delete an item |

The database path comes from `ITEMS_DB` (default `items.db`).

There are no tests yet.
