from langchain.agents import AgentExecutor, create_react_agent
from langchain_openai import ChatOpenAI
from langchain_core.tools import tool


@tool
def lookup_order(order_id: str) -> str:
    """Look an order up."""
    return order_id


llm = ChatOpenAI(model="gpt-4o")
support_executor = AgentExecutor(agent=create_react_agent(llm, [lookup_order], None), tools=[lookup_order])
