import requests
import sys
import re
from pydantic import BaseModel
from openai import OpenAI


if __name__ == "__main__":
    
    question = sys.argv[1]

    prompt = """Write a python one-liner that answers the question, retunring only
    valid python code
    Question
    {question}
    """

    client = OpenAI()

    messages=[
        {"role": "user", "content": prompt.format(
            question=question
            )}
    ]

   

    completion = client.chat.completions.create(
        model="gpt-4o",
        messages=messages,
        )

    code = completion.choices[0].message
    result = exec(code)

    print(result)



    

