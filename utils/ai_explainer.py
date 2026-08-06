import google.generativeai as genai

genai.configure(api_key="YOUR_GEMINI_API_KEY")

model = genai.GenerativeModel("gemini-2.5-flash")

def explain(url, result):

    prompt=f"""
    Analyze this URL.

    URL:
    {url}

    Risk Score:
    {result['score']}

    Reasons:
    {result['reasons']}

    Explain in simple English why this URL is considered safe or suspicious.
    Limit response to 4-5 lines.
    """

    response=model.generate_content(prompt)

    return response.text