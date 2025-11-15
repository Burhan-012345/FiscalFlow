// Chart.js configurations for FiscalFlow
class FiscalFlowCharts {
  static initRevenueExpenseChart(canvasId, data) {
    const ctx = document.getElementById(canvasId).getContext("2d");
    return new Chart(ctx, {
      type: "bar",
      data: {
        labels: data.labels,
        datasets: [
          {
            label: "Revenue",
            data: data.revenue,
            backgroundColor: "rgba(40, 167, 69, 0.8)",
            borderColor: "rgba(40, 167, 69, 1)",
            borderWidth: 1,
          },
          {
            label: "Expenses",
            data: data.expenses,
            backgroundColor: "rgba(220, 53, 69, 0.8)",
            borderColor: "rgba(220, 53, 69, 1)",
            borderWidth: 1,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          y: {
            beginAtZero: true,
            grid: {
              color: "rgba(0, 0, 0, 0.1)",
            },
          },
          x: {
            grid: {
              display: false,
            },
          },
        },
        plugins: {
          legend: {
            position: "top",
          },
          title: {
            display: true,
            text: "Revenue vs Expenses",
          },
        },
      },
    });
  }

  static initBalanceTrendChart(canvasId, data) {
    const ctx = document.getElementById(canvasId).getContext("2d");
    return new Chart(ctx, {
      type: "line",
      data: {
        labels: data.labels,
        datasets: [
          {
            label: "Balance Trend",
            data: data.balances,
            backgroundColor: "rgba(0, 102, 255, 0.1)",
            borderColor: "rgba(0, 102, 255, 1)",
            borderWidth: 2,
            tension: 0.4,
            fill: true,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          y: {
            grid: {
              color: "rgba(0, 0, 0, 0.1)",
            },
          },
          x: {
            grid: {
              display: false,
            },
          },
        },
        plugins: {
          legend: {
            position: "top",
          },
          title: {
            display: true,
            text: "Balance Trend",
          },
        },
      },
    });
  }

  static initCustomerDistributionChart(canvasId, data) {
    const ctx = document.getElementById(canvasId).getContext("2d");
    return new Chart(ctx, {
      type: "doughnut",
      data: {
        labels: data.labels,
        datasets: [
          {
            data: data.values,
            backgroundColor: [
              "rgba(0, 102, 255, 0.8)",
              "rgba(40, 167, 69, 0.8)",
              "rgba(255, 193, 7, 0.8)",
              "rgba(220, 53, 69, 0.8)",
              "rgba(108, 117, 125, 0.8)",
            ],
            borderWidth: 1,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "bottom",
          },
          title: {
            display: true,
            text: "Customer Distribution",
          },
        },
      },
    });
  }

  static initTransactionTypeChart(canvasId, data) {
    const ctx = document.getElementById(canvasId).getContext("2d");
    return new Chart(ctx, {
      type: "pie",
      data: {
        labels: ["Cash In", "Cash Out"],
        datasets: [
          {
            data: [data.cashIn, data.cashOut],
            backgroundColor: [
              "rgba(40, 167, 69, 0.8)",
              "rgba(220, 53, 69, 0.8)",
            ],
            borderWidth: 1,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "bottom",
          },
          title: {
            display: true,
            text: "Transaction Types",
          },
        },
      },
    });
  }
}

// Initialize charts when DOM is loaded
document.addEventListener("DOMContentLoaded", function () {
  // Sample data - in real application, this would come from API
  const sampleData = {
    revenueExpense: {
      labels: ["Jan", "Feb", "Mar", "Apr", "May", "Jun"],
      revenue: [12000, 19000, 15000, 18000, 22000, 25000],
      expenses: [8000, 12000, 10000, 11000, 15000, 18000],
    },
    balanceTrend: {
      labels: ["Jan", "Feb", "Mar", "Apr", "May", "Jun"],
      balances: [4000, 7000, 9000, 10000, 12000, 14000],
    },
    customerDistribution: {
      labels: ["Category A", "Category B", "Category C", "Category D"],
      values: [30, 25, 20, 25],
    },
    transactionTypes: {
      cashIn: 65,
      cashOut: 35,
    },
  };

  // Initialize charts if canvas elements exist
  if (document.getElementById("revenueExpenseChart")) {
    FiscalFlowCharts.initRevenueExpenseChart(
      "revenueExpenseChart",
      sampleData.revenueExpense
    );
  }

  if (document.getElementById("balanceTrendChart")) {
    FiscalFlowCharts.initBalanceTrendChart(
      "balanceTrendChart",
      sampleData.balanceTrend
    );
  }

  if (document.getElementById("customerDistributionChart")) {
    FiscalFlowCharts.initCustomerDistributionChart(
      "customerDistributionChart",
      sampleData.customerDistribution
    );
  }

  if (document.getElementById("transactionTypeChart")) {
    FiscalFlowCharts.initTransactionTypeChart(
      "transactionTypeChart",
      sampleData.transactionTypes
    );
  }
});
