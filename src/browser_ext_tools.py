"""
自定义 Playwright 浏览器扩展工具

继承 LangChain 的 BaseBrowserTool，与 PlayWrightBrowserToolkit 无缝集成。
补充默认 Toolkit 中缺失的关键交互能力：
  - fill_element: 在表单输入框中填写文本
  - select_option: 在下拉框中选择选项
  - wait_for_selector: 等待页面元素出现

设计原则：
  1. 完全复用 BaseBrowserTool 的 sync_browser/async_browser 架构
  2. 通过 get_current_page() 获取当前页面，与其他 Toolkit 工具共享浏览器上下文
  3. 超时和错误处理与 ClickTool 保持一致
"""

from __future__ import annotations

from typing import Optional, Type

from langchain_core.callbacks import (
    AsyncCallbackManagerForToolRun,
    CallbackManagerForToolRun,
)
from langchain_core.pydantic_v1 import BaseModel, Field

from langchain_community.tools.playwright.base import BaseBrowserTool
from langchain_community.tools.playwright.utils import (
    aget_current_page,
    get_current_page,
)


# ========== 1. fill_element 工具 ==========

class FillElementInput(BaseModel):
    """fill_element 工具的输入参数"""
    selector: str = Field(
        ...,
        description="CSS selector for the input element to fill (e.g., 'input[name=\"site_name\"]', '#edit-site-name', 'textarea.comment')"
    )
    value: str = Field(
        ...,
        description="The text value to fill into the input element"
    )


class FillElementTool(BaseBrowserTool):
    """在页面表单元素中填写文本内容。

    支持 input、textarea 等可输入元素。
    会先清空已有内容，再填入新值。

    使用场景：
    - 安装向导中填写站点名称、管理员账号、密码
    - 登录页面输入用户名和密码
    - 搜索框输入查询内容
    """

    name: str = "fill_element"
    description: str = (
        "Fill text into an input/textarea element identified by CSS selector. "
        "Clears existing content before filling. "
        "Input should be a CSS selector and the text value to fill. "
        "Example selectors: 'input[name=\"username\"]', '#edit-pass', 'input[type=\"email\"]'"
    )
    args_schema: Type[BaseModel] = FillElementInput

    visible_only: bool = True
    playwright_timeout: float = 5_000  # 5秒超时，表单元素加载可能较慢

    def _selector_effective(self, selector: str) -> str:
        if not self.visible_only:
            return selector
        return f"{selector} >> visible=1"

    def _run(
        self,
        selector: str,
        value: str,
        run_manager: Optional[CallbackManagerForToolRun] = None,
    ) -> str:
        """同步执行：填写表单元素"""
        if self.sync_browser is None:
            raise ValueError(f"Synchronous browser not provided to {self.name}")
        page = get_current_page(self.sync_browser)
        selector_effective = self._selector_effective(selector)
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError

        try:
            page.fill(
                selector_effective,
                value,
                timeout=self.playwright_timeout,
            )
        except PlaywrightTimeoutError:
            return f"Unable to fill element '{selector}' - element not found or not visible within timeout"
        except Exception as e:
            return f"Error filling element '{selector}': {str(e)}"
        return f"Filled element '{selector}' with value '{value[:50]}{'...' if len(value) > 50 else ''}'"

    async def _arun(
        self,
        selector: str,
        value: str,
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None,
    ) -> str:
        """异步执行：填写表单元素"""
        if self.async_browser is None:
            raise ValueError(f"Asynchronous browser not provided to {self.name}")
        page = await aget_current_page(self.async_browser)
        selector_effective = self._selector_effective(selector)
        from playwright.async_api import TimeoutError as PlaywrightTimeoutError

        try:
            await page.fill(
                selector_effective,
                value,
                timeout=self.playwright_timeout,
            )
        except PlaywrightTimeoutError:
            return f"Unable to fill element '{selector}' - element not found or not visible within timeout"
        except Exception as e:
            return f"Error filling element '{selector}': {str(e)}"
        return f"Filled element '{selector}' with value '{value[:50]}{'...' if len(value) > 50 else ''}'"


# ========== 2. select_option 工具 ==========

class SelectOptionInput(BaseModel):
    """select_option 工具的输入参数"""
    selector: str = Field(
        ...,
        description="CSS selector for the <select> dropdown element (e.g., 'select[name=\"driver\"]', '#edit-db-type')"
    )
    value: str = Field(
        ...,
        description="The option value or visible label to select. Can be the 'value' attribute of <option> or its visible text."
    )


class SelectOptionTool(BaseBrowserTool):
    """在下拉框 (<select>) 中选择指定选项。

    支持按 value 属性或可见文本匹配。

    使用场景：
    - 安装向导中选择数据库类型（如 SQLite）
    - 表单中选择语言、地区等下拉选项
    - 配置页面中选择参数
    """

    name: str = "select_option"
    description: str = (
        "Select an option from a <select> dropdown element by CSS selector. "
        "The value can be the option's 'value' attribute or its visible text label. "
        "Example: selector='select[name=\"driver\"]', value='sqlite' to choose SQLite database."
    )
    args_schema: Type[BaseModel] = SelectOptionInput

    visible_only: bool = True
    playwright_timeout: float = 5_000

    def _selector_effective(self, selector: str) -> str:
        if not self.visible_only:
            return selector
        return f"{selector} >> visible=1"

    def _run(
        self,
        selector: str,
        value: str,
        run_manager: Optional[CallbackManagerForToolRun] = None,
    ) -> str:
        """同步执行：选择下拉框选项"""
        if self.sync_browser is None:
            raise ValueError(f"Synchronous browser not provided to {self.name}")
        page = get_current_page(self.sync_browser)
        selector_effective = self._selector_effective(selector)
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError

        try:
            # 先尝试按 value 属性选择
            result = page.select_option(
                selector_effective,
                value=value,
                timeout=self.playwright_timeout,
            )
            if result:
                return f"Selected option with value '{value}' in '{selector}'"
        except PlaywrightTimeoutError:
            return f"Unable to find select element '{selector}' within timeout"
        except Exception:
            pass

        try:
            # 降级：按可见文本标签选择
            result = page.select_option(
                selector_effective,
                label=value,
                timeout=self.playwright_timeout,
            )
            if result:
                return f"Selected option with label '{value}' in '{selector}'"
        except PlaywrightTimeoutError:
            return f"Unable to find select element '{selector}' within timeout"
        except Exception as e:
            return f"Error selecting option in '{selector}': {str(e)}"

        return f"No matching option '{value}' found in '{selector}'"

    async def _arun(
        self,
        selector: str,
        value: str,
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None,
    ) -> str:
        """异步执行：选择下拉框选项"""
        if self.async_browser is None:
            raise ValueError(f"Asynchronous browser not provided to {self.name}")
        page = await aget_current_page(self.async_browser)
        selector_effective = self._selector_effective(selector)
        from playwright.async_api import TimeoutError as PlaywrightTimeoutError

        try:
            result = await page.select_option(
                selector_effective,
                value=value,
                timeout=self.playwright_timeout,
            )
            if result:
                return f"Selected option with value '{value}' in '{selector}'"
        except PlaywrightTimeoutError:
            return f"Unable to find select element '{selector}' within timeout"
        except Exception:
            pass

        try:
            result = await page.select_option(
                selector_effective,
                label=value,
                timeout=self.playwright_timeout,
            )
            if result:
                return f"Selected option with label '{value}' in '{selector}'"
        except PlaywrightTimeoutError:
            return f"Unable to find select element '{selector}' within timeout"
        except Exception as e:
            return f"Error selecting option in '{selector}': {str(e)}"

        return f"No matching option '{value}' found in '{selector}'"


# ========== 3. wait_for_selector 工具 ==========

class WaitForSelectorInput(BaseModel):
    """wait_for_selector 工具的输入参数"""
    selector: str = Field(
        ...,
        description="CSS selector to wait for (e.g., '#content', '.success-message', 'form#install-form')"
    )
    timeout: int = Field(
        default=10000,
        description="Maximum time to wait in milliseconds (default: 10000ms = 10s)"
    )


class WaitForSelectorTool(BaseBrowserTool):
    """等待页面中指定元素出现。

    在页面加载、AJAX请求、表单提交后的跳转等场景下，
    确保目标元素已渲染完成，再进行后续操作。

    使用场景：
    - 提交表单后等待下一步页面加载
    - 安装向导中等待每一步的内容出现
    - 等待AJAX动态加载的内容
    """

    name: str = "wait_for_selector"
    description: str = (
        "Wait for an element matching the CSS selector to appear on the page. "
        "Useful after navigation, form submission, or AJAX loading. "
        "Returns the element's text content once it appears. "
        "Default timeout is 10 seconds."
    )
    args_schema: Type[BaseModel] = WaitForSelectorInput

    def _run(
        self,
        selector: str,
        timeout: int = 10000,
        run_manager: Optional[CallbackManagerForToolRun] = None,
    ) -> str:
        """同步执行：等待元素出现"""
        if self.sync_browser is None:
            raise ValueError(f"Synchronous browser not provided to {self.name}")
        page = get_current_page(self.sync_browser)
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError

        try:
            element = page.wait_for_selector(
                selector,
                timeout=timeout,
                state="visible",
            )
            if element:
                text = element.text_content() or ""
                # 截取前200字符，避免返回过多内容
                text_preview = text.strip()[:200]
                return f"Element '{selector}' appeared. Content: {text_preview}"
            return f"Element '{selector}' appeared but has no content"
        except PlaywrightTimeoutError:
            return f"Timeout: element '{selector}' did not appear within {timeout}ms"
        except Exception as e:
            return f"Error waiting for '{selector}': {str(e)}"

    async def _arun(
        self,
        selector: str,
        timeout: int = 10000,
        run_manager: Optional[AsyncCallbackManagerForToolRun] = None,
    ) -> str:
        """异步执行：等待元素出现"""
        if self.async_browser is None:
            raise ValueError(f"Asynchronous browser not provided to {self.name}")
        page = await aget_current_page(self.async_browser)
        from playwright.async_api import TimeoutError as PlaywrightTimeoutError

        try:
            element = await page.wait_for_selector(
                selector,
                timeout=timeout,
                state="visible",
            )
            if element:
                text = await element.text_content() or ""
                text_preview = text.strip()[:200]
                return f"Element '{selector}' appeared. Content: {text_preview}"
            return f"Element '{selector}' appeared but has no content"
        except PlaywrightTimeoutError:
            return f"Timeout: element '{selector}' did not appear within {timeout}ms"
        except Exception as e:
            return f"Error waiting for '{selector}': {str(e)}"


# ========== 工具列表导出 ==========

def get_browser_ext_tools(sync_browser=None, async_browser=None) -> list:
    """
    创建所有自定义浏览器扩展工具实例。
    
    参数:
        sync_browser: 同步 Playwright Browser 实例
        async_browser: 异步 Playwright Browser 实例
    
    返回:
        list[BaseBrowserTool]: 工具实例列表
    """
    kwargs = {}
    if sync_browser is not None:
        kwargs["sync_browser"] = sync_browser
    if async_browser is not None:
        kwargs["async_browser"] = async_browser

    return [
        FillElementTool(**kwargs),
        SelectOptionTool(**kwargs),
        WaitForSelectorTool(**kwargs),
    ]
