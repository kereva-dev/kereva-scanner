import requests
import sys
import re
from pydantic import BaseModel
from openai import OpenAI

url = "https://en.wikipedia.org/wiki/Lists_of_Canadians"

class Name(BaseModel):
    name : str

if __name__ == "__main__":
    text = requests.get(url).text
    #crude list of famous people
    items = re.findall("^<li>.*",text, flags=re.MULTILINE)
    
    question = sys.argv[1]

    name_extract = """Extract the name mentioned in the query?
    Query
    {query}
    """

    client = OpenAI()
    completion = client.beta.chat.completions.parse(
    model="gpt-4o",
    messages=[
        {"role": "user", "content": name_extract.format(query=question)},
    ],
    response_format=Name,
    )

    name = completion.choices[0].message.parsed
    print(f"Extracted Name: {name.name}")

    lookup = """
    Based on the information below, answer the question:

    <info>
    {info}
    </info>

    <question>
    {question}
    </question>"""

    info = [l for l in items if name.name.lower() in l.lower()]
    print("Found:")
    for i in info:
        print("\t"+i)

    messages=[
        {"role": "user", "content": lookup.format(
            info="\n\n".join(info),
            question=question
            )}
    ]

   

    completion = client.chat.completions.create(
        model="gpt-4o",
        messages=messages,
        )

    name = completion.choices[0].message

    print(name.content)



    

