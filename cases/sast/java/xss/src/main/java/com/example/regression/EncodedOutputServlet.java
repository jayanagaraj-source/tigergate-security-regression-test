package com.example.regression;

import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.text.StringEscapeUtils;
import org.owasp.encoder.Encode;
import org.springframework.web.util.HtmlUtils;

/** JAVA-011 negatives: numeric values, complete HTML escaping, encoder libraries and constants. */
public class EncodedOutputServlet extends HttpServlet {
    private static final String SHOP = "Regression Shop";

    protected void count(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        int count = Integer.parseInt(req.getParameter("count"));
        resp.getWriter().println("Count: " + count); // JAVA-XSS-TN-001
    }

    protected void total(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        long total = Long.parseLong(req.getParameter("total"));
        resp.getWriter().println("Total " + total + " items"); // JAVA-XSS-TN-002
    }

    protected void average(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        double avg = Double.parseDouble(req.getParameter("avg"));
        resp.getWriter().write("<td>" + avg + "</td>"); // JAVA-XSS-TN-003
    }

    protected void flag(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        boolean enabled = Boolean.parseBoolean(req.getParameter("enabled"));
        resp.getWriter().print("enabled=" + enabled); // JAVA-XSS-TN-004
    }

    protected void escaped(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String raw = req.getParameter("name");
        String safe = raw.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
        resp.getWriter().println("<p>" + safe + "</p>"); // JAVA-XSS-TN-005
    }

    protected void escapedInline(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String raw = req.getParameter("name");
        resp.getWriter().println("<p title=\"" + raw.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;") + "\">"); // JAVA-XSS-TN-006
    }

    protected void owasp(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.getWriter().println("<p>" + Encode.forHtml(req.getParameter("name")) + "</p>"); // JAVA-XSS-TN-007
    }

    protected void commons(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.getWriter().println("<p>" + StringEscapeUtils.escapeHtml4(req.getParameter("name")) + "</p>"); // JAVA-XSS-TN-008
    }

    protected void spring(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.getWriter().write("<p>" + HtmlUtils.htmlEscape(req.getParameter("name")) + "</p>"); // JAVA-XSS-TN-009
    }

    protected void literal(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.getWriter().println("<p>" + "Welcome" + "</p>"); // JAVA-XSS-TN-010
    }

    protected void constant(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.getWriter().println("<h1>" + SHOP + "</h1>"); // JAVA-XSS-TN-011
    }

    protected void shortValue(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        short page = Short.parseShort(req.getParameter("page"));
        resp.getWriter().println("page " + page); // JAVA-XSS-TN-012
    }
}
