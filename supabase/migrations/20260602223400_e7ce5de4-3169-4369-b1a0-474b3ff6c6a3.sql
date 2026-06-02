-- Community threat reports
CREATE TABLE public.community_reports (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID NOT NULL,
  url TEXT NOT NULL,
  category TEXT NOT NULL DEFAULT 'phishing',
  description TEXT,
  risk_score INTEGER NOT NULL DEFAULT 0,
  upvotes INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

GRANT SELECT ON public.community_reports TO anon;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.community_reports TO authenticated;
GRANT ALL ON public.community_reports TO service_role;

ALTER TABLE public.community_reports ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Anyone can view approved reports"
  ON public.community_reports FOR SELECT
  USING (status = 'approved' OR status = 'pending');

CREATE POLICY "Authenticated users can submit reports"
  ON public.community_reports FOR INSERT
  TO authenticated
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update their own reports"
  ON public.community_reports FOR UPDATE
  TO authenticated
  USING (auth.uid() = user_id);

CREATE POLICY "Users can delete their own reports"
  ON public.community_reports FOR DELETE
  TO authenticated
  USING (auth.uid() = user_id);

CREATE TRIGGER update_community_reports_updated_at
  BEFORE UPDATE ON public.community_reports
  FOR EACH ROW
  EXECUTE FUNCTION public.update_updated_at_column();

-- Upvotes (one per user per report)
CREATE TABLE public.report_upvotes (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  report_id UUID NOT NULL REFERENCES public.community_reports(id) ON DELETE CASCADE,
  user_id UUID NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(report_id, user_id)
);

GRANT SELECT, INSERT, DELETE ON public.report_upvotes TO authenticated;
GRANT ALL ON public.report_upvotes TO service_role;

ALTER TABLE public.report_upvotes ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view upvotes"
  ON public.report_upvotes FOR SELECT
  TO authenticated USING (true);

CREATE POLICY "Users can upvote"
  ON public.report_upvotes FOR INSERT
  TO authenticated WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can remove their upvote"
  ON public.report_upvotes FOR DELETE
  TO authenticated USING (auth.uid() = user_id);