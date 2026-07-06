import uvicorn

if __name__ == "__main__":

    print("\n===================================")
    print("SOC SIMULATOR STARTING")
    print("===================================\n")

    uvicorn.run(

        "app.main:app",

        host="127.0.0.1",

        port=8000,

        reload=True,

        log_level="info"
    )