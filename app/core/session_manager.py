import uuid

from datetime import datetime

from app.database.database import (
    get_connection
)

# =========================================
# CREATE NEW SESSION
# =========================================

def create_new_session(

    scan_type="FULL_SCAN"
):

    session_id = str(uuid.uuid4())

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(

        "DELETE FROM active_session"
    )

    cursor.execute("""

    INSERT INTO active_session(

        session_id,
        started_at,
        scan_type

    )

    VALUES(?,?,?)

    """,(

        session_id,

        datetime.now().isoformat(),

        scan_type
    ))

    conn.commit()

    conn.close()

    return session_id

# =========================================
# GET ACTIVE SESSION
# =========================================

def get_active_session():

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""

    SELECT session_id

    FROM active_session

    ORDER BY id DESC

    LIMIT 1

    """)

    row = cursor.fetchone()

    conn.close()

    if row:

        return row[0]

    return None