import pandas as pd


def hunt(df,query):

    if df.empty:return []

    query=query.lower().strip()

    filters={}
    keywords=[]

    for token in query.split():

        if ":" in token:

            k,v=token.split(":",1)

            filters[k]=v

        else:

            keywords.append(token)

    results=[]

    for _,r in df.iterrows():

        text=" ".join(map(str,r.values)).lower()

        # =================================
        # KEYWORD MATCH
        # =================================

        if keywords:

            if not all(k in text for k in keywords):

                continue

        # =================================
        # FILTER MATCH
        # =================================

        matched=True

        for k,v in filters.items():

            value=str(
                r.get(k,"")
            ).lower()

            if v not in value:

                matched=False
                break

        if matched:

            results.append(r.to_dict())

    return results