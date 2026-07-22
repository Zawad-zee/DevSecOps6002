import json

with open('users.json') as f:
    output = json.load(f)
'''print(output)'''
'''print (output[2])'''
print(type(output))
for d in output:
    print(type(d))
    print(d["username"])
    print(d["password"])

