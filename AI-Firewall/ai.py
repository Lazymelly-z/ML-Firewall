import json
import zmq 
import ipaddress
import xgboost as xgb
import pickle
import os
import numpy as np
    
ModelJson = "Model.json"

ColumnMap = {
    "SrcPort":"Source Port",
    "DstPort":"Destination Port",
    "Protocol":"Protocol",
    "PacketLen":"Total Length of Fwd Packets",
}

def BuildVector (Packet:dict, Features:list,):
    LookUp = {
        ColumnMap.get("SrcPort", ""): Packet.get("SrcPort", 0),
        ColumnMap.get("DstPort", ""): Packet.get("DstPort", 0),
        ColumnMap.get("Protocol", ""): Packet.get("Protocol", 0),
        ColumnMap.get("PacketLen", ""): Packet.get("PacketLen", 0),
        "Flags" : Packet.get("Flags", 0) #Flag is calculated in C++ and sent using json
        }

    return np.array([[LookUp.get(col, 0) for col in Features]], dtype =np.float32)

def main ():
    print ("Ai Loading....")

    Model = xgb.XGBClassifier()
    Model.load_model(ModelJson)
    

    with open("Model.pkl", "rb") as f:
        Features = pickle.load(f)["Features"]
        
    print(f"Ai Model loaded features : {Features}")

    Ctx = zmq.Context()
    Socket = Ctx.socket(zmq.REP)
    Socket.bind("tcp://127.0.0.1:5555")
    print("Ai is runnning on port 5555")

    while True :
        try :
            Packet = json.loads(Socket.recv_string())
            FeatureVector = BuildVector(Packet, Features)
            Prediction = Model.predict(FeatureVector)[0]
            Decision = "DROP" if Prediction == 1 else "PASS"

            print(f"{Packet.get('SrcPort')}->"
            f"{Packet.get('DstPort')}\n"
            f"Decision : {Decision}")
            Socket.send_string(Decision)


        except json.JSONDecodeError:
            print("Bad JSON") #Change in prod
            Socket.send_string("PASS")

        except Exception as e:
            print(f"Error or something : {e}")
            Socket.send_string("PASS")

if __name__ == "__main__" :
    main()







