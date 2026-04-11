import { useEffect, useState, useRef } from "react";
import { Navigate } from "react-router-dom";
import { useAuth } from "@/hooks/useAuth";
import { supabase } from "@/integrations/supabase/client";
import { Upload, Database, Trash2, FileText, Loader2, Plus, X } from "lucide-react";
import { toast } from "sonner";
import { analyzeURL } from "@/lib/phishing-analyzer";

interface Dataset {
  id: string;
  name: string;
  description: string | null;
  file_name: string | null;
  total_entries: number;
  malicious_count: number;
  benign_count: number;
  created_at: string;
}

interface DatasetEntry {
  id: string;
  url: string;
  label: string;
  source: string | null;
}

export default function Datasets() {
  const { user, loading } = useAuth();
  const [datasets, setDatasets] = useState<Dataset[]>([]);
  const [selectedDataset, setSelectedDataset] = useState<string | null>(null);
  const [entries, setEntries] = useState<DatasetEntry[]>([]);
  const [uploading, setUploading] = useState(false);
  const [showCreate, setShowCreate] = useState(false);
  const [newName, setNewName] = useState("");
  const [newDesc, setNewDesc] = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!user) return;
    fetchDatasets();
  }, [user]);

  useEffect(() => {
    if (!selectedDataset) { setEntries([]); return; }
    supabase
      .from("dataset_entries")
      .select("id, url, label, source")
      .eq("dataset_id", selectedDataset)
      .limit(500)
      .then(({ data }) => setEntries((data as DatasetEntry[]) || []));
  }, [selectedDataset]);

  const fetchDatasets = async () => {
    const { data } = await supabase.from("datasets").select("*").order("created_at", { ascending: false });
    setDatasets((data as Dataset[]) || []);
  };

  const createDataset = async () => {
    if (!newName.trim() || !user) return;
    const { error } = await supabase.from("datasets").insert({ name: newName.trim(), description: newDesc.trim() || null, user_id: user.id });
    if (error) { toast.error(error.message); return; }
    toast.success("Dataset created!");
    setShowCreate(false);
    setNewName("");
    setNewDesc("");
    fetchDatasets();
  };

  const deleteDataset = async (id: string) => {
    await supabase.from("datasets").delete().eq("id", id);
    if (selectedDataset === id) setSelectedDataset(null);
    fetchDatasets();
    toast.success("Dataset deleted");
  };

  const handleCSVUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !selectedDataset || !user) return;
    setUploading(true);

    try {
      const text = await file.text();
      const lines = text.split("\n").filter((l) => l.trim());
      const hasHeader = lines[0]?.toLowerCase().includes("url");
      const dataLines = hasHeader ? lines.slice(1) : lines;

      let malicious = 0, benign = 0;
      const entriesToInsert = dataLines.slice(0, 10000).map((line) => {
        const parts = line.split(",").map((p) => p.trim().replace(/"/g, ""));
        const url = parts[0] || "";
        let label = (parts[1] || "unknown").toLowerCase();
        if (["1", "malicious", "phishing", "bad", "yes"].includes(label)) { label = "malicious"; malicious++; }
        else if (["0", "benign", "safe", "good", "legitimate", "no"].includes(label)) { label = "benign"; benign++; }
        else label = "unknown";
        return { dataset_id: selectedDataset, user_id: user.id, url, label, source: file.name };
      }).filter((e) => e.url);

      // Batch insert in chunks of 500
      for (let i = 0; i < entriesToInsert.length; i += 500) {
        const chunk = entriesToInsert.slice(i, i + 500);
        await supabase.from("dataset_entries").insert(chunk);
      }

      // Update dataset counts
      await supabase
        .from("datasets")
        .update({
          total_entries: entriesToInsert.length,
          malicious_count: malicious,
          benign_count: benign,
          file_name: file.name,
        })
        .eq("id", selectedDataset);

      toast.success(`Uploaded ${entriesToInsert.length} entries from ${file.name}`);
      fetchDatasets();
      // Refresh entries
      const { data } = await supabase.from("dataset_entries").select("id, url, label, source").eq("dataset_id", selectedDataset).limit(500);
      setEntries((data as DatasetEntry[]) || []);
    } catch (err) {
      toast.error("Failed to parse CSV file");
    }
    setUploading(false);
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  const scanDatasetEntry = (url: string) => {
    const result = analyzeURL(url);
    toast.info(`${url}: ${result.riskLevel.toUpperCase()} (Score: ${result.riskScore})`);
  };

  if (loading) return null;
  if (!user) return <Navigate to="/auth" replace />;

  return (
    <div className="mx-auto max-w-6xl px-4 py-8">
      <div className="mb-6 flex items-center justify-between">
        <h1 className="font-mono text-xl font-bold text-foreground">
          <Database className="mr-2 inline h-5 w-5 text-primary" />
          Datasets
        </h1>
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-1.5 rounded-md bg-primary px-4 py-2 font-mono text-xs font-bold text-primary-foreground hover:opacity-90"
        >
          <Plus className="h-3.5 w-3.5" /> New Dataset
        </button>
      </div>

      {/* Create Dataset Modal */}
      {showCreate && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm">
          <div className="w-full max-w-md rounded-lg border border-border bg-card p-6">
            <div className="mb-4 flex items-center justify-between">
              <h2 className="font-mono text-sm font-bold text-foreground">Create Dataset</h2>
              <button onClick={() => setShowCreate(false)}><X className="h-4 w-4 text-muted-foreground" /></button>
            </div>
            <input
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              placeholder="Dataset name"
              className="mb-3 w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-sm text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none"
            />
            <textarea
              value={newDesc}
              onChange={(e) => setNewDesc(e.target.value)}
              placeholder="Description (optional)"
              className="mb-4 w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-sm text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none"
              rows={3}
            />
            <button
              onClick={createDataset}
              disabled={!newName.trim()}
              className="w-full rounded-md bg-primary py-2 font-mono text-sm font-bold text-primary-foreground hover:opacity-90 disabled:opacity-50"
            >
              Create
            </button>
          </div>
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-3">
        {/* Dataset List */}
        <div className="space-y-2">
          <h3 className="font-mono text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Your Datasets ({datasets.length})
          </h3>
          {datasets.length === 0 ? (
            <div className="rounded-lg border border-border bg-card/30 p-6 text-center">
              <Database className="mx-auto h-8 w-8 text-muted-foreground/30" />
              <p className="mt-2 font-mono text-xs text-muted-foreground">
                No datasets yet. Create one to get started.
              </p>
            </div>
          ) : (
            <div className="space-y-1.5 max-h-[500px] overflow-y-auto">
              {datasets.map((ds) => (
                <button
                  key={ds.id}
                  onClick={() => setSelectedDataset(ds.id)}
                  className={`w-full rounded-md border p-3 text-left transition-colors ${
                    selectedDataset === ds.id
                      ? "border-primary bg-primary/5"
                      : "border-border bg-card/30 hover:bg-secondary/50"
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-semibold text-foreground">{ds.name}</span>
                    <button
                      onClick={(e) => { e.stopPropagation(); deleteDataset(ds.id); }}
                      className="text-muted-foreground hover:text-destructive"
                    >
                      <Trash2 className="h-3 w-3" />
                    </button>
                  </div>
                  <div className="mt-1 flex gap-3 font-mono text-[10px]">
                    <span className="text-muted-foreground">{ds.total_entries} entries</span>
                    <span className="text-destructive">{ds.malicious_count} mal</span>
                    <span className="text-safe">{ds.benign_count} ben</span>
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Dataset Detail */}
        <div className="lg:col-span-2">
          {selectedDataset ? (
            <div className="space-y-4">
              {/* Upload CSV */}
              <div className="rounded-lg border border-dashed border-border bg-card/30 p-6 text-center">
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".csv"
                  onChange={handleCSVUpload}
                  className="hidden"
                  id="csv-upload"
                />
                <label
                  htmlFor="csv-upload"
                  className="cursor-pointer"
                >
                  {uploading ? (
                    <Loader2 className="mx-auto h-8 w-8 animate-spin text-primary" />
                  ) : (
                    <Upload className="mx-auto h-8 w-8 text-muted-foreground/50" />
                  )}
                  <p className="mt-2 font-mono text-xs text-muted-foreground">
                    {uploading ? "Uploading..." : "Click to upload CSV file"}
                  </p>
                  <p className="mt-1 font-mono text-[10px] text-muted-foreground/60">
                    Format: url,label (label: malicious/benign/1/0)
                  </p>
                </label>
              </div>

              {/* Entries Table */}
              {entries.length > 0 && (
                <div className="rounded-lg border border-border bg-card/40 overflow-hidden">
                  <div className="max-h-[400px] overflow-auto">
                    <table className="w-full font-mono text-xs">
                      <thead className="sticky top-0 bg-card">
                        <tr className="border-b border-border text-muted-foreground">
                          <th className="px-3 py-2 text-left">URL</th>
                          <th className="px-3 py-2 text-center">Label</th>
                          <th className="px-3 py-2 text-center">Action</th>
                        </tr>
                      </thead>
                      <tbody>
                        {entries.map((e) => (
                          <tr key={e.id} className="border-b border-border/50 hover:bg-secondary/30">
                            <td className="max-w-[300px] truncate px-3 py-2 text-foreground">{e.url}</td>
                            <td className={`px-3 py-2 text-center font-bold uppercase ${e.label === "malicious" ? "text-destructive" : e.label === "benign" ? "text-safe" : "text-muted-foreground"}`}>
                              {e.label}
                            </td>
                            <td className="px-3 py-2 text-center">
                              <button
                                onClick={() => scanDatasetEntry(e.url)}
                                className="text-primary hover:underline"
                              >
                                Scan
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="flex h-full items-center justify-center rounded-lg border border-border bg-card/20 p-12">
              <div className="text-center">
                <FileText className="mx-auto h-10 w-10 text-muted-foreground/20" />
                <p className="mt-3 font-mono text-xs text-muted-foreground">
                  Select a dataset to view entries or upload a CSV
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
