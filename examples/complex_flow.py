

query = input()

res = openai.Embedding.create(
    input=[query],
    engine=embed_model
)

# retrieve from Pinecone
xq = res['data'][0]['embedding']

# get relevant contexts (including the questions)
res = index.query(xq, top_k=5, include_metadata=True)
     
contexts = [item['metadata']['text'] for item in res['matches']]

jc = "\n\n---\n\n".join(contexts)+"\n\n-----\n\n"

# system message to 'prime' the model
primer = f"""You are Q&A bot. A highly intelligent system that answers
user questions based on the information provided by the user above
each question. If the information can not be found in the information
provided by the user you truthfully say "I don't know".
"""

result = openai.ChatCompletion.create(
    model="gpt-4",
    messages=[
        {"role": "system", "content": primer},
        {"role": "user", "content": jc}
    ]
)

modified_result = result + "some text"

print(result)
print(modified_result)

if "I don't know" in res:
    print("Answer not known")
else:
    print("Answer is known")
